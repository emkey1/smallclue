/*
 * split: GNU coreutils 9 compatible. -l -b -C and -n (N, K/N, l/N, l/K/N,
 * r/N, r/K/N, the remainder going to the first chunks), -a with GNU's
 * suffix auto-widening (...yz then zaaa, ...89 then 9000), -d/-x with
 * their =FROM, --additional-suffix, -e, -t, --filter (FILE in its
 * environment), --verbose, the obsolete -NUM, and GNU's messages.
 */

#include "split_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { SPLIT_LINES, SPLIT_BYTES, SPLIT_LINE_BYTES, SPLIT_CHUNK_BYTES, SPLIT_CHUNK_LINES, SPLIT_RR };

typedef struct {
    const char *alphabet;
    const char *prefix, *addsuf, *filter;
    int suffixLength;
    bool suffixAuto, verbose, elide;
    char *base;           /* prefix plus absorbed widening characters */
    int *idx;
    char *name;
    bool started;
    int outFd;
    FILE *outPipe;
    const char *inName;
    struct stat inSt;
    bool inStOk;
    int status;
} Split;

static int splitTry(void) {
    fputs("Try 'split --help' for more information.\n", stderr);
    return 1;
}

/* xstrtoimax, base 10, "bEGKkMmPQRTYZ0" suffixes; false when invalid. */
static bool splitSize(const char *s, intmax_t *out) {
    char *end;
    errno = 0;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '-') return false;
    uintmax_t v = strtoumax(s, &end, 10);
    if (end == s) return false;
    if (*end) {
        uintmax_t mult = 1;
        unsigned base = 1024;
        size_t used = 1;
        if (*end == 'b') mult = 512;
        else {
            if (end[1] == 'i' && end[2] == 'B') used = 3;
            else if (end[1] == 'B' || end[1] == 'D') base = 1000, used = 2;
            static const char pw[] = "KMGTPEZYRQ";
            char up = *end == 'k' ? 'K' : *end == 'm' ? 'M' : *end;
            const char *pos = strchr(pw, up);
            if (!pos) return false;
            for (int i = 0; i <= pos - pw; i++) mult = mult > UINTMAX_MAX / base ? UINTMAX_MAX : mult * base;
        }
        if (end[used]) return false;
        v = v && mult > UINTMAX_MAX / v ? UINTMAX_MAX : v * mult;
    }
    *out = v > INTMAX_MAX || errno == ERANGE ? INTMAX_MAX : (intmax_t)v;
    return true;
}

static bool splitNextName(Split *s) {
    size_t alen = strlen(s->alphabet);
    if (s->started) {
        int i = s->suffixLength;
        while (i-- > 0) {
            s->idx[i]++;
            if (s->suffixAuto && i == 0 && s->idx[0] + 1 >= (int)alen) goto widen;
            if (s->idx[i] < (int)alen) goto build;
            s->idx[i] = 0;
        }
        fputs("split: output file suffixes exhausted\n", stderr);
        return false;
    widen: {
            size_t bl = strlen(s->base);
            char *nb = (char *)malloc(bl + 2);
            memcpy(nb, s->base, bl);
            nb[bl] = s->alphabet[s->idx[0]];
            nb[bl + 1] = '\0';
            free(s->base);
            s->base = nb;
            s->suffixLength++;
            free(s->idx);
            s->idx = (int *)calloc((size_t)s->suffixLength, sizeof(int));
        }
    }
build:
    s->started = true;
    size_t bl = strlen(s->base), al = s->addsuf ? strlen(s->addsuf) : 0;
    free(s->name);
    s->name = (char *)malloc(bl + (size_t)s->suffixLength + al + 1);
    memcpy(s->name, s->base, bl);
    for (int i = 0; i < s->suffixLength; i++) s->name[bl + i] = s->alphabet[s->idx[i]];
    memcpy(s->name + bl + s->suffixLength, s->addsuf ? s->addsuf : "", al + 1);
    return true;
}

static bool splitClose(Split *s) {
    char q[4096];
    bool ok = true;
    if (s->outPipe) {
        int st = pclose(s->outPipe);
        s->outPipe = NULL;
        if (st != 0 && st != -1) {
            if (WIFEXITED(st)) fprintf(stderr, "split: with FILE=%s, exit %d from command: %s\n", s->name, WEXITSTATUS(st), s->filter);
            else fprintf(stderr, "split: with FILE=%s, signal %d from command: %s\n", s->name, WTERMSIG(st), s->filter);
            ok = false;
        }
    } else if (s->outFd >= 0) {
        if (close(s->outFd) != 0) {
            fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s->name, q, sizeof(q)), strerror(errno));
            ok = false;
        }
    }
    s->outFd = -1;
    return ok;
}

/* The next output file, opened. */
static bool splitOpen(Split *s) {
    char q[4096];
    if (!splitClose(s) || !splitNextName(s)) return false;
    if (s->verbose) printf("creating file %s\n", gnuQuote(s->name, q, sizeof(q)));
    if (s->filter) {
        fflush(stdout);
        setenv("FILE", s->name, 1);
        s->outPipe = popen(s->filter, "w");
        if (!s->outPipe) {
            fprintf(stderr, "split: failed to run command: \"%s -c %s\": %s\n", "/bin/sh", s->filter, strerror(errno));
            return false;
        }
        return true;
    }
    s->outFd = open(s->name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (s->outFd < 0) {
        fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s->name, q, sizeof(q)), strerror(errno));
        return false;
    }
    struct stat st;
    if (s->inStOk && fstat(s->outFd, &st) == 0 && st.st_dev == s->inSt.st_dev && st.st_ino == s->inSt.st_ino &&
        S_ISREG(st.st_mode)) {
        fprintf(stderr, "split: %s would overwrite input; aborting\n", gnuQuote(s->name, q, sizeof(q)));
        return false;
    }
    return true;
}

static bool splitWrite(Split *s, const char *b, size_t n) {
    char q[4096];
    if (!n) return true;
    if (s->outPipe) {
        if (fwrite(b, 1, n, s->outPipe) != n) {
            fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s->name, q, sizeof(q)), strerror(errno));
            return false;
        }
        return true;
    }
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(s->outFd, b + done, n - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s->name, q, sizeof(q)), strerror(errno));
            return false;
        }
        done += (size_t)w;
    }
    return true;
}

static bool splitReadAll(Split *s, FILE *in, char **out, size_t *len) {
    char q[4096];
    size_t cap = 65536, n = 0;
    char *b = (char *)malloc(cap);
    size_t r;
    while (b && (r = fread(b + n, 1, cap - n, in)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = (char *)realloc(b, cap *= 2);
            if (!nb) break;
            b = nb;
        }
    }
    if (ferror(in)) {
        fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s->inName, q, sizeof(q)), strerror(errno));
        free(b);
        return false;
    }
    *out = b;
    *len = n;
    return true;
}

static const GnuLongOpt splitLongs[] = {
    {"bytes", GNU_REQ_ARG, 'b'},          {"lines", GNU_REQ_ARG, 'l'},
    {"line-bytes", GNU_REQ_ARG, 'C'},     {"number", GNU_REQ_ARG, 'n'},
    {"elide-empty-files", GNU_NO_ARG, 'e'}, {"unbuffered", GNU_NO_ARG, 'u'},
    {"suffix-length", GNU_REQ_ARG, 'a'},  {"additional-suffix", GNU_REQ_ARG, 1},
    {"numeric-suffixes", GNU_OPT_ARG, 'd'}, {"hex-suffixes", GNU_OPT_ARG, 'x'},
    {"filter", GNU_REQ_ARG, 2},           {"verbose", GNU_NO_ARG, 3},
    {"separator", GNU_REQ_ARG, 't'},      {"help", GNU_NO_ARG, 4},
    {"version", GNU_NO_ARG, 5},
};

int smallclueSplitCommand(int argc, char **argv) {
    Split s;
    memset(&s, 0, sizeof(s));
    s.alphabet = "abcdefghijklmnopqrstuvwxyz";
    s.prefix = "x";
    s.suffixLength = 2;
    s.suffixAuto = true;
    s.outFd = -1;
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "split", "0123456789C:a:b:d::el:n:t:ux::", splitLongs,
                  sizeof(splitLongs) / sizeof(splitLongs[0]));
    int type = -1, c, status = 1;
    intmax_t size = 1000, chunkK = 0, chunkN = 0;
    const char *numStart = NULL;
    char sep = '\n';
    bool sepSet = false, suffixSet = false, digitsMode = false;
    char q[4096], digits[32];
    size_t ndigits = 0;
    int digitsInd = -1;
    FILE *in = NULL;
    char *data = NULL;
    while ((c = gnuGetopt(&g)) != -1) {
        if (c >= '0' && c <= '9') {
            /* -NUM: digits of one argument; a later argument starts over */
            if (type != -1 && !digitsMode) {
                fputs("split: cannot split in more than one way\n", stderr);
                goto try;
            }
            if (digitsInd != g.ind) ndigits = 0;
            digitsInd = g.ind;
            if (ndigits + 1 < sizeof(digits)) digits[ndigits++] = (char)c;
            digits[ndigits] = '\0';
            type = SPLIT_LINES;
            digitsMode = true;
            size = strtoimax(digits, NULL, 10);
            continue;
        }
        switch (c) {
        case 'a':
            {
                char *end;
                long v = strtol(g.arg, &end, 10);
                if (end == g.arg || *end || v < 0 || v > 1000) {
                    fprintf(stderr, "split: invalid suffix length: %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                    goto done;
                }
                if (v) s.suffixLength = (int)v, suffixSet = true;
                s.suffixAuto = false;
            }
            break;
        case 'b': case 'C': case 'l': {
            int want = c == 'b' ? SPLIT_BYTES : c == 'C' ? SPLIT_LINE_BYTES : SPLIT_LINES;
            if (type != -1) {
                fputs("split: cannot split in more than one way\n", stderr);
                goto try;
            }
            type = want;
            if (!splitSize(g.arg, &size) || size == 0) {
                fprintf(stderr, "split: invalid number of %s: %s\n", c == 'l' ? "lines" : "bytes", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto done;
            }
            break;
        }
        case 'n': {
            if (type != -1) {
                fputs("split: cannot split in more than one way\n", stderr);
                goto try;
            }
            const char *a = g.arg;
            type = SPLIT_CHUNK_BYTES;
            if (!strncmp(a, "r/", 2)) type = SPLIT_RR, a += 2;
            else if (!strncmp(a, "l/", 2)) type = SPLIT_CHUNK_LINES, a += 2;
            const char *slash = strchr(a, '/');
            char kbuf[64];
            if (slash) {
                snprintf(kbuf, sizeof(kbuf), "%.*s", (int)(slash - a), a);
                if (!splitSize(kbuf, &chunkK) || chunkK == 0) {
                    fprintf(stderr, "split: invalid chunk number: %s\n", gnuQuoteLocale(kbuf, q, sizeof(q)));
                    goto done;
                }
                a = slash + 1;
            }
            if (!splitSize(a, &chunkN) || chunkN == 0) {
                fprintf(stderr, "split: invalid number of chunks: %s\n", gnuQuoteLocale(a, q, sizeof(q)));
                goto done;
            }
            if (chunkK > chunkN) {
                fprintf(stderr, "split: invalid chunk number: %s\n", gnuQuoteLocale(kbuf, q, sizeof(q)));
                goto done;
            }
            break;
        }
        case 'd': case 'x':
            s.alphabet = c == 'd' ? "0123456789" : "0123456789abcdef";
            if (g.arg) {
                numStart = g.arg;
                for (const char *p = g.arg; *p; p++)
                    if (!strchr(s.alphabet, *p)) {
                        fprintf(stderr, "split: %s: invalid start value for %s suffix\n", gnuQuoteLocale(g.arg, q, sizeof(q)),
                                c == 'd' ? "numerical" : "hexadecimal");
                        goto done;
                    }
            }
            break;
        case 'e': s.elide = true; break;
        case 'u': break;
        case 't': {
            const char *a = g.arg;
            char ch = a[0];
            if (a[0] && a[1]) {
                if (!strcmp(a, "\\0")) ch = '\0';
                else {
                    fprintf(stderr, "split: multi-character separator %s\n", gnuQuoteLocale(a, q, sizeof(q)));
                    goto done;
                }
            } else if (!a[0]) {
                fputs("split: empty record separator\n", stderr);
                goto done;
            }
            if (sepSet && ch != sep) {
                fputs("split: multiple separator characters specified\n", stderr);
                goto done;
            }
            sep = ch;
            sepSet = true;
            break;
        }
        case 1:
            if (strchr(g.arg, '/')) {
                fprintf(stderr, "split: invalid suffix %s, contains directory separator\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto try;
            }
            s.addsuf = g.arg;
            break;
        case 2: s.filter = g.arg; break;
        case 3: s.verbose = true; break;
        case 4:
            fputs("Usage: split [OPTION]... [FILE [PREFIX]]\n"
                  "Output pieces of FILE to PREFIXaa, PREFIXab, ...;\n"
                  "default size is 1000 lines, and default PREFIX is 'x'.\n",
                  stdout);
            status = 0;
            goto done;
        case 5: puts("split (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    if (type == -1) type = SPLIT_LINES;
    if (g.nops > 2) {
        fprintf(stderr, "split: extra operand %s\n", gnuQuoteLocale(g.ops[2], q, sizeof(q)));
        goto try;
    }
    s.inName = g.nops >= 1 ? g.ops[0] : "-";
    if (g.nops == 2) s.prefix = g.ops[1];
    /* suffix length: a numeric start or -n's count may need more */
    if (numStart || type == SPLIT_CHUNK_BYTES || type == SPLIT_CHUNK_LINES || type == SPLIT_RR) {
        s.suffixAuto = false;
        uintmax_t last = (type >= SPLIT_CHUNK_BYTES ? (uintmax_t)chunkN - 1 : 0) + (numStart ? strtoumax(numStart, NULL, (int)strlen(s.alphabet)) : 0);
        int need = 1;
        for (uintmax_t v = last / strlen(s.alphabet); v; v /= strlen(s.alphabet)) need++;
        int startLen = numStart ? (int)strlen(numStart) : 0;
        if (need < startLen) need = startLen;
        if (suffixSet) {
            if (s.suffixLength < need) {
                fprintf(stderr, "split: the suffix length needs to be at least %d\n", need);
                goto done;
            }
        } else if (need > s.suffixLength) {
            s.suffixLength = need;
        }
    }
    s.base = strdup(s.prefix);
    s.idx = (int *)calloc((size_t)s.suffixLength + 1, sizeof(int));
    if (numStart) {
        size_t sl = strlen(numStart);
        for (size_t i = 0; i < sl; i++)
            s.idx[s.suffixLength - sl + i] = (int)(strchr(s.alphabet, numStart[i]) - s.alphabet);
    }
    if (!strcmp(s.inName, "-")) {
        in = stdin;
    } else if (!(in = smallclueAppOpenRead(s.inName))) {
        fprintf(stderr, "split: cannot open %s for reading: %s\n", gnuQuote(s.inName, q, sizeof(q)), strerror(errno));
        goto done;
    }
    s.inStOk = fstat(fileno(in), &s.inSt) == 0;
    status = 0;
    if (type == SPLIT_LINES || type == SPLIT_BYTES || type == SPLIT_LINE_BYTES) {
        char buf[65536];
        size_t r;
        intmax_t cur = 0;   /* lines or bytes in the current file */
        bool isOpen = false;
        /* -C: a line that does not fit waits in hold until it does */
        char *hold = NULL;
        size_t holdLen = 0, holdCap = 0;
        while ((r = fread(buf, 1, sizeof(buf), in)) > 0) {
            size_t p = 0;
            while (p < r) {
                if (type == SPLIT_LINE_BYTES) {
                    char *nl = memchr(buf + p, sep, r - p);
                    size_t take = nl ? (size_t)(nl - (buf + p)) + 1 : r - p;
                    if (holdLen + take > holdCap) {
                        holdCap = (holdLen + take) * 2;
                        hold = (char *)realloc(hold, holdCap);
                    }
                    memcpy(hold + holdLen, buf + p, take);
                    holdLen += take;
                    p += take;
                    if (!nl) continue;   /* a line still being read */
                    /* a whole line in hold: place it */
                    size_t off = 0;
                    while (off < holdLen) {
                        size_t rest = holdLen - off;
                        if (isOpen && cur + (intmax_t)rest <= size) {
                            if (!splitWrite(&s, hold + off, rest)) goto fail;
                            cur += (intmax_t)rest;
                            off = holdLen;
                        } else if (isOpen && cur > 0) {
                            isOpen = false;
                        } else {
                            if (!splitOpen(&s)) goto fail;
                            isOpen = true;
                            cur = 0;
                            size_t piece = rest < (size_t)size ? rest : (size_t)size;
                            if (!splitWrite(&s, hold + off, piece)) goto fail;
                            cur = (intmax_t)piece;
                            off += piece;
                        }
                    }
                    holdLen = 0;
                    continue;
                }
                if (!isOpen || cur >= size) {
                    if (!splitOpen(&s)) goto fail;
                    isOpen = true;
                    cur = 0;
                }
                size_t take;
                if (type == SPLIT_BYTES) {
                    take = r - p;
                    if ((intmax_t)take > size - cur) take = (size_t)(size - cur);
                    cur += (intmax_t)take;
                } else {
                    char *nl = memchr(buf + p, sep, r - p);
                    take = nl ? (size_t)(nl - (buf + p)) + 1 : r - p;
                    if (nl) cur++;
                }
                if (!splitWrite(&s, buf + p, take)) goto fail;
                p += take;
            }
        }
        if (type == SPLIT_LINE_BYTES && holdLen) {
            size_t off = 0;
            while (off < holdLen) {
                size_t rest = holdLen - off;
                if (isOpen && cur + (intmax_t)rest <= size) {
                    if (!splitWrite(&s, hold + off, rest)) goto fail;
                    off = holdLen;
                } else if (isOpen && cur > 0) {
                    isOpen = false;
                } else {
                    if (!splitOpen(&s)) goto fail;
                    isOpen = true;
                    size_t piece = rest < (size_t)size ? rest : (size_t)size;
                    if (!splitWrite(&s, hold + off, piece)) goto fail;
                    cur = (intmax_t)piece;
                    off += piece;
                }
            }
        }
        free(hold);
        if (ferror(in)) {
            fprintf(stderr, "split: %s: %s\n", gnuQuoteMaybe(s.inName, q, sizeof(q)), strerror(errno));
            goto fail;
        }
    } else {
        size_t len;
        if (!splitReadAll(&s, in, &data, &len)) goto fail;
        intmax_t n = chunkN;
        if (type == SPLIT_RR) {
            /* lines dealt round the files */
            char **names = NULL;
            int *fds = (int *)malloc((size_t)n * sizeof(int));
            FILE **pipes = (FILE **)calloc((size_t)n, sizeof(FILE *));
            names = (char **)calloc((size_t)n, sizeof(char *));
            if (!chunkK) {
                for (intmax_t k = 0; k < n; k++) {
                    if (!splitOpen(&s)) goto fail;
                    fds[k] = s.outFd;
                    pipes[k] = s.outPipe;
                    names[k] = strdup(s.name);
                    s.outFd = -1;
                    s.outPipe = NULL;
                }
            }
            size_t p = 0;
            for (intmax_t line = 0; p < len; line++) {
                char *nl = memchr(data + p, sep, len - p);
                size_t take = nl ? (size_t)(nl - (data + p)) + 1 : len - p;
                intmax_t k = line % n;
                if (chunkK) {
                    if (k == chunkK - 1) fwrite(data + p, 1, take, stdout);
                } else {
                    s.outFd = fds[k];
                    s.outPipe = pipes[k];
                    free(s.name);
                    s.name = strdup(names[k]);
                    if (!splitWrite(&s, data + p, take)) goto fail;
                }
                p += take;
            }
            if (!chunkK)
                for (intmax_t k = 0; k < n; k++) {
                    s.outFd = fds[k];
                    s.outPipe = pipes[k];
                    free(s.name);
                    s.name = names[k];
                    names[k] = NULL;
                    splitClose(&s);
                    struct stat st;
                    if (s.elide && !s.filter && stat(s.name, &st) == 0 && st.st_size == 0) unlink(s.name);
                }
            s.outFd = -1;
            free(fds);
            free(pipes);
            for (intmax_t k = 0; k < n; k++) free(names[k]);
            free(names);
        } else {
            size_t q0 = len / (size_t)n, r0 = len % (size_t)n, pos = 0;
            for (intmax_t k = 1; k <= n; k++) {
                size_t endExcl = (size_t)k * q0 + ((size_t)k < r0 ? (size_t)k : r0);
                size_t from = pos, to;
                if (type == SPLIT_CHUNK_BYTES) {
                    from = (size_t)(k - 1) * q0 + ((size_t)(k - 1) < r0 ? (size_t)(k - 1) : r0);
                    to = endExcl;
                } else if (k == n) {
                    to = len;
                } else if (pos >= endExcl || endExcl == 0) {
                    to = pos;
                } else {
                    char *nl = memchr(data + endExcl - 1, sep, len - (endExcl - 1));
                    to = nl ? (size_t)(nl - data) + 1 : len;
                }
                if (to < from) to = from;
                pos = to;
                if (chunkK) {
                    if (k == chunkK) fwrite(data + from, 1, to - from, stdout);
                    continue;
                }
                if (s.elide && to == from) continue;
                if (!splitOpen(&s) || !splitWrite(&s, data + from, to - from)) goto fail;
            }
        }
    }
    if (!splitClose(&s)) status = 1;
    goto done;
fail:
    splitClose(&s);
    status = 1;
    goto done;
try:
    status = splitTry();
done:
    free(data);
    if (in && in != stdin) fclose(in);
    free(s.base);
    free(s.idx);
    free(s.name);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("split", errno);
        status = 1;
    }
    return status;
}
