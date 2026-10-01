/*
 * cmp: GNU diffutils' byte-by-byte comparison -- the first difference as
 * "differ: char N, line L" ("byte" outside the C locale), -l every one,
 * -b the bytes themselves, -s only the status; -i/SKIP operands and -n,
 * with GNU's number syntax (0x/0 prefixes, K/M/G..., KB/KiB); the EOF
 * messages; and the same-file short cut.
 */

#include "cmp_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum { CMP_FIRST, CMP_ALL, CMP_STATUS };

typedef struct {
    const char *name;
    FILE *f;
    struct stat st;
    uintmax_t skip;
    unsigned char buf[16384];
    size_t len, pos;
    bool eof;
} CmpFile;

static int cmpTry(void) {
    fputs("cmp: Try 'cmp --help' for more information.\n", stderr);
    return 2;
}

/* gnulib xstrtoumax, base 0, suffixes "kKMGTPEZY0": 0 ok, 1 invalid, 2 a
 * bad suffix character (where *end points), 3 overflow. */
static int cmpNumber(const char *s, const char **end, uintmax_t *out) {
    const char *q = s;
    while (isspace((unsigned char)*q)) q++;
    if (*q == '-') return 1;
    char *e;
    errno = 0;
    uintmax_t v = strtoumax(s, &e, 0);
    int status = errno == ERANGE ? 3 : 0;
    static const char suffixes[] = "kKMGTPEZY";
    if (e == s) {
        if (!*e || !strchr(suffixes, *e)) return 1;
        v = 1;
    }
    *end = e;
    if (!*e) {
        *out = v;
        return status;
    }
    if (!strchr(suffixes, *e)) {
        *out = v;
        return 2;
    }
    unsigned base = 1024;
    size_t used = 1;
    if (e[1] == 'i' && e[2] == 'B') used = 3;
    else if (e[1] == 'B' || e[1] == 'D') base = 1000, used = 2;
    int power = (int)(strchr("kKMGTPEZY", *e) - "kKMGTPEZY");
    power = power < 2 ? 1 : power;
    for (int i = 0; i < power; i++) {
        if (v > UINTMAX_MAX / base) status = 3, v = UINTMAX_MAX;
        else v *= base;
    }
    *end = e + used;
    *out = v;
    if (**end) return 2;
    return status;
}

/* GNU's parse_ignore_initial: a SKIP, ended by `delim` when not '\0'. */
static bool cmpSkip(const char **arg, char delim, uintmax_t *out) {
    const char *start = *arg, *end = start;
    int e = cmpNumber(start, &end, out);
    if (!(e == 0 || (e == 2 && delim && *end == delim)) || *out > (uintmax_t)INT64_MAX) {
        fprintf(stderr, "cmp: invalid --ignore-initial value '%s'\n", start);
        return false;
    }
    *arg = end;
    return true;
}

/* GNU's sprintc: ^X for controls, M- for the high half. */
static const char *cmpChar(unsigned char c, char out[5]) {
    char *p = out;
    if (!(c >= 32 && c < 127)) {
        if (c >= 128) *p++ = 'M', *p++ = '-', c -= 128;
        if (c < 32) *p++ = '^', c += 64;
        else if (c == 127) *p++ = '^', c = '?';
    }
    *p++ = (char)c;
    *p = '\0';
    return out;
}

/* "char" in the C locale, as POSIX has it; "byte" elsewhere. */
static bool cmpHardLocale(void) {
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_MESSAGES");
    if (!v || !*v) v = getenv("LANG");
    return v && *v && strcmp(v, "C") && strcmp(v, "POSIX");
}

static bool cmpFill(CmpFile *f, int *status) {
    if (f->pos < f->len || f->eof) return true;
    f->len = fread(f->buf, 1, sizeof(f->buf), f->f);
    f->pos = 0;
    if (f->len == 0) {
        if (ferror(f->f)) {
            fprintf(stderr, "cmp: %s: %s\n", f->name, strerror(errno));
            *status = 2;
            return false;
        }
        f->eof = true;
    }
    return true;
}

static bool cmpSkipInput(CmpFile *f, int *status) {
    if (!f->skip) return true;
    if (S_ISREG(f->st.st_mode) && fseeko(f->f, (off_t)f->skip, SEEK_CUR) == 0) return true;
    for (uintmax_t left = f->skip; left;) {
        if (!cmpFill(f, status)) return false;
        if (f->eof) break;
        size_t n = f->len - f->pos;
        if (n > left) n = (size_t)left;
        f->pos += n;
        left -= n;
    }
    return true;
}

static int cmpCompare(CmpFile *f, int type, bool bytes, uintmax_t limit) {
    int width = 1;
    if (type == CMP_ALL) {
        uintmax_t most = limit < (uintmax_t)INT64_MAX ? limit : (uintmax_t)INT64_MAX;
        for (int i = 0; i < 2; i++)
            if (S_ISREG(f[i].st.st_mode)) {
                off_t at = ftello(f[i].f);
                intmax_t left = (intmax_t)f[i].st.st_size - (at < 0 ? 0 : (intmax_t)at) + (intmax_t)f[i].pos -
                                (intmax_t)f[i].len;
                if (left < 0) left = 0;
                if ((uintmax_t)left < most) most = (uintmax_t)left;
            }
        while ((most /= 10) != 0) width++;
    }
    uintmax_t byte = 0, line = 1;
    bool atLineStart = false;
    int status = 0;
    char c0s[5], c1s[5];
    while (byte < limit) {
        if (!cmpFill(&f[0], &status) || !cmpFill(&f[1], &status)) return 2;
        if (f[0].eof || f[1].eof) {
            if (f[0].eof && f[1].eof) break;
            if (type != CMP_STATUS) {
                const char *shorter = f[0].eof ? f[0].name : f[1].name;
                if (byte == 0)
                    fprintf(stderr, "cmp: EOF on %s which is empty\n", shorter);
                else if (type == CMP_ALL)
                    fprintf(stderr, "cmp: EOF on %s after byte %ju\n", shorter, byte);
                else if (atLineStart)
                    fprintf(stderr, "cmp: EOF on %s after byte %ju, line %ju\n", shorter, byte, line - 1);
                else
                    fprintf(stderr, "cmp: EOF on %s after byte %ju, in line %ju\n", shorter, byte, line);
            }
            return 1;
        }
        size_t n = f[0].len - f[0].pos;
        if (f[1].len - f[1].pos < n) n = f[1].len - f[1].pos;
        if (limit - byte < n) n = (size_t)(limit - byte);
        const unsigned char *a = f[0].buf + f[0].pos, *b = f[1].buf + f[1].pos;
        for (size_t k = 0; k < n; k++) {
            byte++;
            if (a[k] != b[k]) {
                if (type == CMP_STATUS) return 1;
                if (type == CMP_FIRST) {
                    if (bytes)
                        printf("%s %s differ: byte %ju, line %ju is %3o %s %3o %s\n", f[0].name, f[1].name, byte,
                               line, a[k], cmpChar(a[k], c0s), b[k], cmpChar(b[k], c1s));
                    else
                        printf(cmpHardLocale() ? "%s %s differ: byte %ju, line %ju\n"
                                               : "%s %s differ: char %ju, line %ju\n",
                               f[0].name, f[1].name, byte, line);
                    return 1;
                }
                if (bytes)
                    printf("%*ju %3o %-4s %3o %s\n", width, byte, a[k], cmpChar(a[k], c0s), b[k],
                           cmpChar(b[k], c1s));
                else
                    printf("%*ju %3o %3o\n", width, byte, a[k], b[k]);
                status = 1;
            }
            atLineStart = a[k] == '\n';
            if (atLineStart) line++;
        }
        f[0].pos += n;
        f[1].pos += n;
    }
    return status;
}

static const GnuLongOpt cmpLongs[] = {
    {"print-bytes", GNU_NO_ARG, 'b'}, {"print-chars", GNU_NO_ARG, 'c'}, {"ignore-initial", GNU_REQ_ARG, 'i'},
    {"verbose", GNU_NO_ARG, 'l'},     {"bytes", GNU_REQ_ARG, 'n'},      {"silent", GNU_NO_ARG, 's'},
    {"quiet", GNU_NO_ARG, 's'},       {"version", GNU_NO_ARG, 'v'},     {"help", GNU_NO_ARG, 1},
};

int smallclueCmpCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "cmp", "bci:ln:sv", cmpLongs, sizeof(cmpLongs) / sizeof(cmpLongs[0]));
    int type = CMP_FIRST, status = 2, c;
    bool bytes = false, sawL = false, sawS = false;
    uintmax_t limit = UINTMAX_MAX, skip[2] = {0, 0};
    CmpFile *f = NULL;
    while ((c = gnuGetopt(&g)) != -1) {
        const char *p = g.arg, *end;
        uintmax_t v;
        switch (c) {
        case 'b': case 'c': bytes = true; break;
        case 'i':
            if (!cmpSkip(&p, ':', &skip[0])) goto try;
            if (*p == ':') {
                p++;
                if (!cmpSkip(&p, '\0', &skip[1])) goto try;
            } else {
                skip[1] = skip[0];
            }
            break;
        case 'l': type = CMP_ALL; sawL = true; break;
        case 'n':
            if (cmpNumber(g.arg, &end, &v) != 0) {
                fprintf(stderr, "cmp: invalid --bytes value '%s'\n", g.arg);
                goto try;
            }
            if (v < limit) limit = v;
            break;
        case 's': type = CMP_STATUS; sawS = true; break;
        case 'v': puts("cmp (SmallCLUE) 3.10"); status = 0; goto done;
        case 1:
            fputs("Usage: cmp [OPTION]... FILE1 [FILE2 [SKIP1 [SKIP2]]]\n"
                  "Compare two files byte by byte.\n\n"
                  "The optional SKIP1 and SKIP2 specify the number of bytes to skip\n"
                  "at the beginning of each file (zero by default).\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -b, --print-bytes          print differing bytes\n"
                  "  -i, --ignore-initial=SKIP         skip first SKIP bytes of both inputs\n"
                  "  -i, --ignore-initial=SKIP1:SKIP2  skip first SKIP1 bytes of FILE1 and\n"
                  "                                      first SKIP2 bytes of FILE2\n"
                  "  -l, --verbose              output byte numbers and differing byte values\n"
                  "  -n, --bytes=LIMIT          compare at most LIMIT bytes\n"
                  "  -s, --quiet, --silent      suppress all normal output\n"
                  "      --help                 display this help and exit\n"
                  "  -v, --version              output version information and exit\n\n"
                  "SKIP values may be followed by the following multiplicative suffixes:\n"
                  "kB 1000, K 1024, MB 1,000,000, M 1,048,576,\n"
                  "GB 1,000,000,000, G 1,073,741,824, and so on for T, P, E, Z, Y.\n\n"
                  "If a FILE is '-' or missing, read standard input.\n"
                  "Exit status is 0 if inputs are the same, 1 if different, 2 if trouble.\n",
                  stdout);
            status = 0;
            goto done;
        default: goto try;
        }
    }
    if (sawL && sawS) {
        fputs("cmp: options -l and -s are incompatible\n", stderr);
        goto try;
    }
    if (g.nops == 0) {
        fprintf(stderr, "cmp: missing operand after '%s'\n", argv[argc - 1]);
        goto try;
    }
    if (g.nops > 4) {
        fprintf(stderr, "cmp: extra operand '%s'\n", g.ops[4]);
        goto try;
    }
    for (int i = 0; i < 2 && i + 2 < g.nops; i++) {
        const char *p = g.ops[i + 2];
        uintmax_t v;
        if (!cmpSkip(&p, '\0', &v)) goto try;
        if (v > skip[i]) skip[i] = v;
    }
    f = (CmpFile *)calloc(2, sizeof(CmpFile));
    if (!f) goto done;
    for (int i = 0; i < 2; i++) {
        f[i].name = i < g.nops ? g.ops[i] : "-";
        f[i].skip = skip[i];
        if (!strcmp(f[i].name, "-")) {
            f[i].f = stdin;
        } else if (!(f[i].f = smallclueAppOpenRead(f[i].name))) {
            fprintf(stderr, "cmp: %s: %s\n", f[i].name, strerror(errno));
            goto done;
        }
        if (fstat(fileno(f[i].f), &f[i].st) != 0) {
            fprintf(stderr, "cmp: %s: %s\n", f[i].name, strerror(errno));
            goto done;
        }
    }
    /* One file at the same position is the same, unread. */
    if (f[0].st.st_dev == f[1].st.st_dev && f[0].st.st_ino == f[1].st.st_ino) {
        off_t p0 = ftello(f[0].f), p1 = ftello(f[1].f);
        if ((uintmax_t)p0 + skip[0] == (uintmax_t)p1 + skip[1]) {
            status = 0;
            goto done;
        }
    }
    status = 0;
    if (!cmpSkipInput(&f[0], &status) || !cmpSkipInput(&f[1], &status)) goto done;
    status = cmpCompare(f, type, bytes, limit);
    goto done;
try:
    status = cmpTry();
done:
    if (f) {
        for (int i = 0; i < 2; i++)
            if (f[i].f && f[i].f != stdin) fclose(f[i].f);
        free(f);
    }
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status < 2) status = 2;
    return status;
}
