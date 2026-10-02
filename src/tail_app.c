/*
 * tail: output the last part of files, compatible with GNU coreutils 9.
 *
 * The tail this replaces took -n and -f only: no -c, no -q/-v/-z, no -F,
 * -f on one input only and never with -n +NUM. This has GNU's options and
 * suffixes, the obsolete `tail -NUM` / `tail +NUM` forms, headers, -f and -F
 * (--follow=name --retry) over any number of files with GNU's truncation,
 * replacement and disappearance messages, --pid, -s, and GNU's exit
 * statuses.
 *
 * A regular file's last lines are found by reading backwards from its end,
 * so `tail big.log` costs only what it prints. Other input is read through,
 * keeping only what may still be printed.
 *
 * Following polls (GNU uses inotify); every pass checks the host's
 * interrupt hook so an embedded `tail -f` can be stopped.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tail_app.h"
#include "app_hooks.h"
#include "gnu_size.h"
#include "gnu_util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum { TAIL_FOLLOW_NONE, TAIL_FOLLOW_DESCRIPTOR, TAIL_FOLLOW_NAME };

typedef struct {
    bool bytes;        /* -c */
    bool fromStart;    /* +NUM */
    uintmax_t count;
    char delim;        /* '\n', or '\0' with -z */
    int headers;       /* -1 never (-q), 0 auto, 1 always (-v) */
    int follow;
    bool retry;
    double sleep;
    long pid;
} TailOptions;

typedef struct {
    const char *name;  /* as given; "-" is standard input */
    FILE *fp;
    int fd;            /* -1 while closed */
    off_t pos;
    dev_t dev;
    ino_t ino;
    mode_t mode;
    bool ignore;       /* given up on */
    bool reported;     /* inaccessibility already said */
    bool pipe;         /* standard input that is a pipe: never followed */
} TailFile;

typedef struct {
    const TailOptions *o;
    bool headers;
    int last;          /* the file whose output came last, -1 for none */
    bool writeFailed;
    int status;
} TailState;

static const char *tailPretty(const TailFile *f) {
    return strcmp(f->name, "-") ? f->name : "standard input";
}

static ssize_t tailRead(int fd, char *buf, size_t size) {
    for (;;) {
        ssize_t n = read(fd, buf, size);
        if (n >= 0 || errno != EINTR) return n;
    }
}

static void tailHeader(TailState *s, int index, const TailFile *f) {
    if (s->headers && s->last != index)
        printf("%s==> %s <==\n", s->last < 0 ? "" : "\n", tailPretty(f));
    s->last = index;
}

static bool tailWrite(TailState *s, const char *buf, size_t n) {
    if (n && fwrite(buf, 1, n, stdout) != n) {
        s->writeFailed = true;
        return false;
    }
    return true;
}

static void tailReadError(TailState *s, const TailFile *f) {
    char q[4096];
    fprintf(stderr, "tail: error reading %s: %s\n", gnuQuote(tailPretty(f), q, sizeof(q)), strerror(errno));
    s->status = 1;
}

/* Copies fd to stdout until EOF (or EAGAIN); returns bytes copied, -1 on a
 * read error. */
static intmax_t tailCopyRest(TailState *s, int fd) {
    char buf[65536];
    intmax_t total = 0;
    for (;;) {
        ssize_t n = tailRead(fd, buf, sizeof(buf));
        if (n < 0) return errno == EAGAIN ? total : -1;
        if (n == 0) return total;
        if (!tailWrite(s, buf, (size_t)n)) return total;
        total += n;
    }
}

/* +NUM: skip NUM-1 lines or bytes, then copy the rest. */
static bool tailFromStart(TailState *s, int fd, const struct stat *st) {
    const TailOptions *o = s->o;
    uintmax_t skip = o->count ? o->count - 1 : 0;
    if (o->bytes && S_ISREG(st->st_mode) && skip > 0) {
        if (lseek(fd, (off_t)skip, SEEK_CUR) >= 0) skip = 0;
    }
    char buf[65536];
    while (skip > 0) {
        ssize_t n = tailRead(fd, buf, sizeof(buf));
        if (n < 0) return false;
        if (n == 0) return true;
        size_t i = 0;
        if (o->bytes) {
            i = (uintmax_t)n < skip ? (size_t)n : (size_t)skip;
            skip -= i;
        } else {
            while (i < (size_t)n && skip > 0)
                if (buf[i++] == o->delim) skip--;
        }
        if (skip == 0 && !tailWrite(s, buf + i, (size_t)n - i)) return true;
    }
    return tailCopyRest(s, fd) >= 0;
}

/* The last NUM lines or bytes of a regular file, read backwards from its
 * end. */
static bool tailRegular(TailState *s, int fd, const struct stat *st) {
    const TailOptions *o = s->o;
    off_t base = lseek(fd, 0, SEEK_CUR);
    off_t end = st->st_size;
    if (base < 0 || end <= base) return tailCopyRest(s, fd) >= 0;
    off_t start = base;
    if (o->bytes) {
        if ((uintmax_t)(end - base) > o->count) start = end - (off_t)o->count;
    } else if (o->count == 0) {
        start = end;
    } else {
        char buf[65536];
        uintmax_t left = o->count;
        off_t pos = end;
        bool found = false;
        while (pos > base && !found) {
            off_t chunk = pos - base < (off_t)sizeof(buf) ? pos - base : (off_t)sizeof(buf);
            off_t at = pos - chunk;
            if (lseek(fd, at, SEEK_SET) < 0) return false;
            size_t have = 0;
            while (have < (size_t)chunk) {
                ssize_t n = tailRead(fd, buf + have, (size_t)chunk - have);
                if (n < 0) return false;
                if (n == 0) break;
                have += (size_t)n;
            }
            for (size_t i = have; i-- > 0;) {
                off_t abs = at + (off_t)i;
                /* A delimiter that ends the file ends the last line. */
                if (buf[i] != o->delim || abs == end - 1) continue;
                if (--left == 0) {
                    start = abs + 1;
                    found = true;
                    break;
                }
            }
            pos = at;
        }
    }
    if (lseek(fd, start, SEEK_SET) < 0) return false;
    return tailCopyRest(s, fd) >= 0;
}

/* Where the last `count` lines of buf start; `atEnd` when buf ends the
 * input, so a final delimiter closes the last line. */
static size_t tailLinesStart(const char *buf, size_t len, uintmax_t count, char delim, bool atEnd) {
    if (count == 0) return len;
    size_t pos = len;
    if (atEnd && pos > 0 && buf[pos - 1] == delim) pos--;
    while (pos > 0) {
        if (buf[pos - 1] == delim && --count == 0) return pos;
        pos--;
    }
    return 0;
}

/* Input that cannot be read backwards: read it all, keeping only what may
 * still be printed. */
static bool tailStream(TailState *s, int fd) {
    const TailOptions *o = s->o;
    size_t cap = 65536, len = 0, trimAt = 1 << 20;
    char *data = (char *)malloc(cap);
    if (!data) { errno = ENOMEM; return false; }
    for (;;) {
        if (len == cap) {
            char *n = (char *)realloc(data, cap * 2);
            if (!n) { free(data); errno = ENOMEM; return false; }
            data = n;
            cap *= 2;
        }
        ssize_t got = tailRead(fd, data + len, cap - len);
        if (got < 0) { free(data); return false; }
        if (got == 0) break;
        len += (size_t)got;
        if (len >= trimAt) {
            size_t from;
            if (o->bytes) {
                from = (uintmax_t)len > o->count ? len - (size_t)o->count : 0;
            } else {
                /* Keep one line more than asked: the last may be partial. */
                uintmax_t want = o->count == UINTMAX_MAX ? o->count : o->count + 1;
                from = tailLinesStart(data, len, want, o->delim, false);
            }
            if (from > 0) {
                memmove(data, data + from, len - from);
                len -= from;
            }
            if (len * 2 > trimAt) trimAt = len * 2;
        }
    }
    size_t from;
    if (o->bytes)
        from = (uintmax_t)len > o->count ? len - (size_t)o->count : 0;
    else
        from = tailLinesStart(data, len, o->count, o->delim, true);
    tailWrite(s, data + from, len - from);
    free(data);
    return true;
}

static bool tailOpen(TailFile *f) {
    if (!strcmp(f->name, "-")) {
        f->fp = NULL;
        f->fd = 0;
    } else {
        f->fp = smallclueAppOpenRead(f->name);
        if (!f->fp) return false;
        f->fd = fileno(f->fp);
    }
    struct stat st;
    if (fstat(f->fd, &st) == 0) {
        f->dev = st.st_dev;
        f->ino = st.st_ino;
        f->mode = st.st_mode;
    }
    return true;
}

static void tailClose(TailFile *f) {
    if (f->fp) fclose(f->fp);
    f->fp = NULL;
    f->fd = -1;
}

/* The first output of one file. */
static void tailInitial(TailState *s, TailFile *f, int index) {
    char q[4096];
    if (!tailOpen(f)) {
        int e = errno;
        fprintf(stderr, "tail: cannot open %s for reading: %s\n", gnuQuote(tailPretty(f), q, sizeof(q)), strerror(e));
        s->status = 1;
        f->reported = true;
        f->fd = -1;
        /* Only following by name, with retrying, keeps watching for it. */
        f->ignore = !(s->o->follow == TAIL_FOLLOW_NAME && s->o->retry);
        return;
    }
    struct stat st;
    if (fstat(f->fd, &st) != 0) {
        tailReadError(s, f);
        tailClose(f);
        f->ignore = true;
        return;
    }
    tailHeader(s, index, f);
    bool ok;
    if (S_ISDIR(st.st_mode)) {
        errno = EISDIR;
        ok = false;
    } else if (s->o->fromStart) {
        ok = tailFromStart(s, f->fd, &st);
    } else if (S_ISREG(st.st_mode) && st.st_size > 0) {
        ok = tailRegular(s, f->fd, &st);
    } else {
        ok = tailStream(s, f->fd);
    }
    if (!ok) {
        tailReadError(s, f);
        if (s->o->follow != TAIL_FOLLOW_NONE && S_ISDIR(st.st_mode)) {
            fprintf(stderr, "tail: %s: cannot follow end of this type of file; giving up on this name\n",
                    gnuQuoteMaybe(tailPretty(f), q, sizeof(q)));
        }
        tailClose(f);
        f->ignore = true;
        return;
    }
    off_t pos = lseek(f->fd, 0, SEEK_CUR);
    f->pos = pos < 0 ? 0 : pos;
    /* Standard input that is a pipe or FIFO is not followed (POSIX). */
    if (!strcmp(f->name, "-") && (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)))
        f->ignore = f->pipe = true;
    else if (!S_ISREG(st.st_mode)) {
        int fl = fcntl(f->fd, F_GETFL);
        if (fl >= 0) (void)fcntl(f->fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* -F: has the name gone away, come back, or been replaced? */
static void tailRecheckName(TailState *s, TailFile *f, int index) {
    char q[4096];
    struct stat st;
    if (!strcmp(f->name, "-")) return;
    if (stat(f->name, &st) != 0) {
        if (f->fd >= 0 || !f->reported) {
            fprintf(stderr, "tail: %s has become inaccessible: %s\n", gnuQuote(f->name, q, sizeof(q)), strerror(errno));
            f->reported = true;
        }
        if (f->fd >= 0) tailClose(f);
        if (!s->o->retry) f->ignore = true;
        return;
    }
    if (f->fd >= 0 && st.st_dev == f->dev && st.st_ino == f->ino) return;
    bool replaced = f->fd >= 0;
    if (f->fd >= 0) {
        /* Drain what was written to the old file before it went. */
        if (S_ISREG(f->mode)) {
            tailHeader(s, index, f);
            (void)tailCopyRest(s, f->fd);
        }
        tailClose(f);
    }
    if (!tailOpen(f)) {
        if (!f->reported) {
            fprintf(stderr, "tail: cannot open %s for reading: %s\n", gnuQuote(f->name, q, sizeof(q)), strerror(errno));
            f->reported = true;
        }
        f->fd = -1;
        return;
    }
    fprintf(stderr, "tail: %s has %s;  following new file\n", gnuQuote(f->name, q, sizeof(q)),
            replaced ? "been replaced" : "appeared");
    f->reported = false;
    f->pos = 0;
    if (!S_ISREG(f->mode)) {
        int fl = fcntl(f->fd, F_GETFL);
        if (fl >= 0) (void)fcntl(f->fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* One pass over the followed files; true when anything was printed. */
static bool tailPass(TailState *s, TailFile *files, int n) {
    char q[4096];
    bool any = false;
    for (int i = 0; i < n && !s->writeFailed; i++) {
        TailFile *f = &files[i];
        if (f->ignore) continue;
        if (s->o->follow == TAIL_FOLLOW_NAME) tailRecheckName(s, f, i);
        if (f->fd < 0 || f->ignore) continue;
        if (S_ISREG(f->mode)) {
            struct stat st;
            if (fstat(f->fd, &st) != 0) continue;
            if (st.st_size < f->pos) {
                fprintf(stderr, "tail: %s: file truncated\n", gnuQuoteMaybe(tailPretty(f), q, sizeof(q)));
                (void)lseek(f->fd, 0, SEEK_SET);
                f->pos = 0;
            }
            if (st.st_size == f->pos) continue;
            if (lseek(f->fd, f->pos, SEEK_SET) < 0) continue;
        }
        char buf[65536];
        ssize_t got = tailRead(f->fd, buf, sizeof(buf));
        if (got < 0) {
            if (errno != EAGAIN) {
                tailReadError(s, f);
                tailClose(f);
                f->ignore = true;
            }
            continue;
        }
        if (got == 0) continue;
        tailHeader(s, i, f);
        if (!tailWrite(s, buf, (size_t)got)) break;
        intmax_t more = tailCopyRest(s, f->fd);
        off_t pos = lseek(f->fd, 0, SEEK_CUR);
        f->pos = pos >= 0 ? pos : f->pos + got + (more > 0 ? more : 0);
        any = true;
    }
    if (any && fflush(stdout) != 0) s->writeFailed = true;
    return any;
}

static bool tailPidAlive(long pid) {
    return kill((pid_t)pid, 0) == 0 || errno != ESRCH;
}

/* GNU's check_output_alive: a pipe or socket whose reader has gone shows
 * POLLERR or POLLHUP on our end, and tail -f | head would otherwise wait
 * forever, since nothing is written to draw the SIGPIPE. */
static bool tailOutputGone(void) {
    struct stat st;
    if (fstat(STDOUT_FILENO, &st) != 0 || !(S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))) return false;
    struct pollfd pfd = {STDOUT_FILENO, POLLRDBAND, 0};
    return poll(&pfd, 1, 0) >= 0 && (pfd.revents & (POLLERR | POLLHUP));
}

static int tailForever(TailState *s, TailFile *files, int n) {
    struct timespec nap;
    nap.tv_sec = (time_t)s->o->sleep;
    nap.tv_nsec = (long)((s->o->sleep - (double)nap.tv_sec) * 1e9);
    for (;;) {
        int st = 0;
        if (smallclueAppShouldAbort(&st)) return st ? st : 130;
        bool alive = s->o->pid == 0 || tailPidAlive(s->o->pid);
        bool any = tailPass(s, files, n);
        if (s->writeFailed) return 1;
        int viable = 0;
        for (int i = 0; i < n; i++)
            if (!files[i].ignore) viable++;
        if (viable == 0) {
            fprintf(stderr, "tail: no files remaining\n");
            return 1;
        }
        if (!alive) return s->status;
        if (tailOutputGone()) {
            raise(SIGPIPE);
            return 1;
        }
        if (!any) nanosleep(&nap, NULL);
    }
}

static void tailUsage(void) {
    fputs("Usage: tail [OPTION]... [FILE]...\n"
          "Print the last 10 lines of each FILE to standard output.\n"
          "With more than one FILE, precede each with a header giving the file name.\n"
          "\n"
          "With no FILE, or when FILE is -, read standard input.\n"
          "\n"
          "  -c, --bytes=[+]NUM       output the last NUM bytes; or use -c +NUM to\n"
          "                             output starting with byte NUM of each file\n"
          "  -f, --follow[={name|descriptor}]\n"
          "                           output appended data as the file grows;\n"
          "                             an absent option argument means 'descriptor'\n"
          "  -F                       same as --follow=name --retry\n"
          "  -n, --lines=[+]NUM       output the last NUM lines, instead of the last 10;\n"
          "                             or use -n +NUM to skip NUM-1 lines at the start\n"
          "      --max-unchanged-stats=N  accepted; following polls every pass\n"
          "      --pid=PID            with -f, terminate after process ID, PID dies\n"
          "  -q, --quiet, --silent    never output headers giving file names\n"
          "      --retry              keep trying to open a file if it is inaccessible\n"
          "  -s, --sleep-interval=N   with -f, sleep for approximately N seconds\n"
          "                             (default 0.25) between iterations\n"
          "  -v, --verbose            always output headers giving file names\n"
          "  -z, --zero-terminated    line delimiter is NUL, not newline\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n"
          "\n"
          "NUM may have a multiplier suffix:\n"
          "b 512, kB 1000, K 1024, MB 1000*1000, M 1024*1024,\n"
          "GB 1000*1000*1000, G 1024*1024*1024, and so on for T, P, E, Z, Y, R, Q.\n"
          "Binary prefixes can be used, too: KiB=K, MiB=M, and so on.\n",
          stdout);
}

static bool tailParseCount(const char *s, bool bytes, TailOptions *o) {
    char q[512];
    const char *p = s;
    bool fromStart = *p == '+';
    if (*p == '+' || *p == '-') p++;
    uintmax_t v;
    int r = gnuParseSize(p, &v);
    if (r == 2) {
        v = UINTMAX_MAX; /* GNU takes a count too large as "all" */
        r = 0;
    }
    if (r != 0) {
        fprintf(stderr, "tail: invalid number of %s: %s\n", bytes ? "bytes" : "lines",
                gnuQuoteLocale(s, q, sizeof(q)));
        return false;
    }
    o->bytes = bytes;
    o->fromStart = fromStart;
    o->count = v;
    return true;
}

static int tailTry(const char *fmt, const char *a) {
    fprintf(stderr, fmt, a);
    fputs("Try 'tail --help' for more information.\n", stderr);
    return 1;
}

/* GNU's obsolete syntax: `tail [+-][NUM][bcl][f] [FILE]`, only as the sole
 * option with at most one file after it. */
static bool tailObsolete(int argc, char **argv, TailOptions *o) {
    if (!(argc == 2 || (argc == 3 && !(argv[2][0] == '-' && argv[2][1]))))
        return false;
    const char *p = argv[1];
    bool fromStart;
    if (*p == '+') fromStart = true;
    else if (*p == '-' && p[1] != '\0' && p[1] != 'c') fromStart = false;
    else if (*p == '-' && p[1] == 'c' && p[2] != '\0') fromStart = false;
    else return false;
    p++;
    const char *digits = p;
    while (*p >= '0' && *p <= '9') p++;
    uintmax_t v = 10;
    if (p > digits) v = strtoumax(digits, NULL, 10);
    bool bytes = false;
    if (*p == 'b') { bytes = true; v *= 512; p++; }
    else if (*p == 'c') { bytes = true; p++; }
    else if (*p == 'l') p++;
    bool follow = false;
    if (*p == 'f') { follow = true; p++; }
    if (*p != '\0') return false;
    o->fromStart = fromStart;
    o->bytes = bytes;
    o->count = v;
    if (follow) o->follow = TAIL_FOLLOW_DESCRIPTOR;
    return true;
}

int smallclueTailCommand(int argc, char **argv) {
    smallclueAppClearPendingSignals();
    TailOptions o = {false, false, 10, '\n', 0, TAIL_FOLLOW_NONE, false, 0.25, 0};
    char **names = (char **)calloc((size_t)argc + 1, sizeof(char *));
    TailFile *files = NULL;
    int nnames = 0, status = 0;
    if (!names) return 1;

    int start = 1;
    if (tailObsolete(argc, argv, &o)) start = 2;

    bool endOfOptions = false;
    for (int i = start; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            names[nnames++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *val = strchr(opt, '=');
            size_t len = val ? (size_t)(val - opt) : strlen(opt);
            if (val) val++;
            static const char *const longs[] = {
                "bytes", "follow", "lines", "max-unchanged-stats", "pid", "quiet", "retry",
                "silent", "sleep-interval", "verbose", "zero-terminated", "help", "version",
            };
            const int nlongs = (int)(sizeof(longs) / sizeof(longs[0]));
            int match = -1, matches = 0;
            for (int k = 0; k < nlongs; k++) {
                if (!strncmp(longs[k], opt, len)) {
                    if (strlen(longs[k]) == len) { match = k; matches = 1; break; }
                    match = k;
                    matches++;
                }
            }
            if (matches != 1) {
                status = tailTry(matches ? "tail: option '%s' is ambiguous\n" : "tail: unrecognized option '%s'\n", arg);
                goto done;
            }
            const char *name = longs[match];
            bool needsArg = match == 0 || match == 2 || match == 3 || match == 4 || match == 8;
            if (needsArg && !val) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "tail: option '--%s' requires an argument\n", name);
                    status = tailTry("%s", "");
                    goto done;
                }
                val = argv[++i];
            }
            if (!needsArg && val && match != 1) {
                fprintf(stderr, "tail: option '--%s' doesn't allow an argument\n", name);
                status = tailTry("%s", "");
                goto done;
            }
            char q[512];
            switch (match) {
            case 0: case 2:
                if (!tailParseCount(val, match == 0, &o)) { status = 1; goto done; }
                break;
            case 1:
                if (!val || !strcmp(val, "descriptor")) o.follow = TAIL_FOLLOW_DESCRIPTOR;
                else if (!strcmp(val, "name")) o.follow = TAIL_FOLLOW_NAME;
                else {
                    char q2[64], q3[64], q4[64];
                    fprintf(stderr, "tail: invalid argument %s for %s\n"
                                    "Valid arguments are:\n  - %s\n  - %s\n",
                            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale("--follow", q2, sizeof(q2)),
                            gnuQuoteLocale("descriptor", q3, sizeof(q3)), gnuQuoteLocale("name", q4, sizeof(q4)));
                    status = tailTry("%s", "");
                    goto done;
                }
                break;
            case 3: {
                uintmax_t ignored;
                if (gnuParseSize(val, &ignored) != 0) {
                    fprintf(stderr, "tail: invalid maximum number of unchanged stats between opens: %s\n",
                            gnuQuoteLocale(val, q, sizeof(q)));
                    status = 1;
                    goto done;
                }
                break;
            }
            case 4: {
                char *end;
                long pid = strtol(val, &end, 10);
                if (*val == '\0' || *end != '\0' || pid < 0) {
                    fprintf(stderr, "tail: invalid PID: %s\n", gnuQuoteLocale(val, q, sizeof(q)));
                    status = 1;
                    goto done;
                }
                o.pid = pid;
                break;
            }
            case 5: case 7: o.headers = -1; break;
            case 6: o.retry = true; break;
            case 8: {
                char *end;
                double d = strtod(val, &end);
                if (*val == '\0' || *end != '\0' || d < 0) {
                    fprintf(stderr, "tail: invalid number of seconds: %s\n", gnuQuoteLocale(val, q, sizeof(q)));
                    status = 1;
                    goto done;
                }
                o.sleep = d;
                break;
            }
            case 9: o.headers = 1; break;
            case 10: o.delim = '\0'; break;
            case 11: tailUsage(); goto done;
            default: puts("tail (SmallCLUE) 9.4"); goto done;
            }
            continue;
        }
        for (const char *c = arg + 1; *c; c++) {
            if (*c == 'c' || *c == 'n' || *c == 's') {
                const char *val = c[1] ? c + 1 : NULL;
                if (!val) {
                    if (i + 1 >= argc) {
                        char opt[2] = {*c, '\0'};
                        status = tailTry("tail: option requires an argument -- '%s'\n", opt);
                        goto done;
                    }
                    val = argv[++i];
                }
                if (*c == 's') {
                    char *end;
                    char q[512];
                    double d = strtod(val, &end);
                    if (*val == '\0' || *end != '\0' || d < 0) {
                        fprintf(stderr, "tail: invalid number of seconds: %s\n", gnuQuoteLocale(val, q, sizeof(q)));
                        status = 1;
                        goto done;
                    }
                    o.sleep = d;
                } else if (!tailParseCount(val, *c == 'c', &o)) {
                    status = 1;
                    goto done;
                }
                break;
            }
            if (*c == 'f') { if (o.follow == TAIL_FOLLOW_NONE) o.follow = TAIL_FOLLOW_DESCRIPTOR; }
            else if (*c == 'F') { o.follow = TAIL_FOLLOW_NAME; o.retry = true; }
            else if (*c == 'q') o.headers = -1;
            else if (*c == 'v') o.headers = 1;
            else if (*c == 'z') o.delim = '\0';
            else {
                char opt[2] = {*c, '\0'};
                status = tailTry("tail: invalid option -- '%s'\n", opt);
                goto done;
            }
        }
    }

    if (o.retry && o.follow == TAIL_FOLLOW_NONE)
        fprintf(stderr, "tail: warning: --retry ignored; --retry is useful only when following\n");
    else if (o.retry && o.follow == TAIL_FOLLOW_DESCRIPTOR)
        fprintf(stderr, "tail: warning: --retry only effective for the initial open\n");
    if (o.pid && o.follow == TAIL_FOLLOW_NONE)
        fprintf(stderr, "tail: warning: PID ignored; --pid=PID is useful only when following\n");

    if (nnames == 0) names[nnames++] = (char *)"-";
    files = (TailFile *)calloc((size_t)nnames, sizeof(TailFile));
    if (!files) { status = 1; goto done; }
    TailState s = {&o, o.headers == 1 || (o.headers == 0 && nnames > 1), -1, false, 0};
    for (int i = 0; i < nnames; i++) {
        files[i].name = names[i];
        files[i].fd = -1;
        tailInitial(&s, &files[i], i);
        if (s.writeFailed) break;
    }
    status = s.status;
    if (!s.writeFailed && o.follow != TAIL_FOLLOW_NONE) {
        /* Only when every input is a piped standard input is there
         * nothing to follow and nothing to say; otherwise the loop reports
         * "no files remaining" once all are given up on. */
        int viable = 0;
        for (int i = 0; i < nnames; i++)
            if (!files[i].pipe) viable++;
        if (viable > 0) {
            if (fflush(stdout) != 0) s.writeFailed = true;
            else status = tailForever(&s, files, nnames);
        }
    }
    if (s.writeFailed) status = 1;
    for (int i = 0; i < nnames; i++)
        if (files[i].fd >= 0) tailClose(&files[i]);

done:
    if (fflush(stdout) != 0 || ferror(stdout)) {
        if (errno != EPIPE) fprintf(stderr, "tail: error writing 'standard output': %s\n", strerror(errno));
        status = 1;
    }
    free(files);
    free(names);
    return status;
}
