/*
 * head: output the first part of files, compatible with GNU coreutils 9.
 *
 * The head this replaces took -n N and -n -N only: no -c (so `head -c 16
 * /dev/urandom` and every byte-counting script failed), no -q/-v, no -z, no
 * size suffixes. This has GNU's options, its multiplier suffixes, the
 * obsolete `head -NUM` form, "==> NAME <==" headers, and GNU's messages and
 * exit statuses.
 *
 * Input is read with read(2), not stdio: fread would wait for a full buffer,
 * and `slow-producer | head -n 1` must finish at the first line. Like GNU,
 * a regular file's offset is left just past what was printed, so
 * `{ head -n 1; cat; } < file` splits the file.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "head_app.h"
#include "app_hooks.h"
#include "gnu_size.h"
#include "gnu_util.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    bool bytes;        /* -c */
    bool allBut;       /* a leading '-': all but the last N */
    uintmax_t count;
    char delim;        /* '\n', or '\0' with -z */
    int headers;       /* -1 never (-q), 0 auto, 1 always (-v) */
} HeadOptions;

static ssize_t headRead(int fd, char *buf, size_t size) {
    for (;;) {
        ssize_t n = read(fd, buf, size);
        if (n >= 0 || errno != EINTR) return n;
    }
}

static bool headWrite(const char *buf, size_t n) {
    return fwrite(buf, 1, n, stdout) == n;
}

/* 0 ok, 1 read error (errno set), 2 write error. */
static int headFirst(int fd, const HeadOptions *o) {
    char buf[65536];
    uintmax_t left = o->count;
    while (left > 0) {
        size_t want = sizeof(buf);
        if (o->bytes && left < want) want = (size_t)left;
        ssize_t got = headRead(fd, buf, want);
        if (got < 0) return 1;
        if (got == 0) break;
        size_t end = (size_t)got;
        if (o->bytes) {
            left -= (uintmax_t)got;
        } else {
            end = 0;
            while (end < (size_t)got && left > 0)
                if (buf[end++] == o->delim) left--;
            /* Leave the rest of a regular file unread. */
            if (left == 0 && end < (size_t)got) {
                struct stat st;
                if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
                    (void)lseek(fd, (off_t)end - (off_t)got, SEEK_CUR);
            }
        }
        if (!headWrite(buf, end)) return 2;
    }
    return 0;
}

/* Everything but the last `count` lines or bytes: read it all, then cut. */
static int headAllBut(int fd, const HeadOptions *o) {
    size_t cap = 65536, len = 0;
    char *data = (char *)malloc(cap);
    if (!data) { errno = ENOMEM; return 1; }
    for (;;) {
        if (len == cap) {
            char *n = (char *)realloc(data, cap * 2);
            if (!n) { free(data); errno = ENOMEM; return 1; }
            data = n;
            cap *= 2;
        }
        ssize_t got = headRead(fd, data + len, cap - len);
        if (got < 0) { free(data); return 1; }
        if (got == 0) break;
        len += (size_t)got;
    }
    size_t keep;
    if (o->bytes) {
        keep = o->count >= len ? 0 : len - (size_t)o->count;
    } else {
        /* Walk back over `count` lines; a last line without a delimiter
         * is a line too. */
        size_t pos = len;
        uintmax_t left = o->count;
        if (left > 0 && pos > 0 && data[pos - 1] == o->delim) pos--;
        while (left > 0 && pos > 0) {
            while (pos > 0 && data[pos - 1] != o->delim) pos--;
            left--;
            if (left > 0 && pos > 0) pos--;
        }
        keep = pos;
    }
    int r = keep && !headWrite(data, keep) ? 2 : 0;
    free(data);
    return r;
}

/* false on a failure that should end the command (a write error). */
static bool headFile(const char *name, const HeadOptions *o, bool header, bool *first, int *status) {
    char q[4096];
    FILE *fp = NULL;
    int fd = 0;
    bool isStdin = !strcmp(name, "-");
    if (!isStdin) {
        fp = smallclueAppOpenRead(name);
        if (!fp) {
            fprintf(stderr, "head: cannot open %s for reading: %s\n", gnuQuote(name, q, sizeof(q)), strerror(errno));
            *status = 1;
            return true;
        }
        fd = fileno(fp);
    }
    if (header)
        printf("%s==> %s <==\n", *first ? "" : "\n", isStdin ? "standard input" : name);
    *first = false;
    int r = o->allBut ? headAllBut(fd, o) : headFirst(fd, o);
    if (r == 1) {
        fprintf(stderr, "head: error reading %s: %s\n", gnuQuote(isStdin ? "standard input" : name, q, sizeof(q)), strerror(errno));
        *status = 1;
    }
    if (fp) fclose(fp);
    return r != 2;
}

static void headUsage(void) {
    fputs("Usage: head [OPTION]... [FILE]...\n"
          "Print the first 10 lines of each FILE to standard output.\n"
          "With more than one FILE, precede each with a header giving the file name.\n"
          "\n"
          "With no FILE, or when FILE is -, read standard input.\n"
          "\n"
          "  -c, --bytes=[-]NUM       print the first NUM bytes of each file;\n"
          "                             with the leading '-', print all but the last\n"
          "                             NUM bytes of each file\n"
          "  -n, --lines=[-]NUM       print the first NUM lines instead of the first 10;\n"
          "                             with the leading '-', print all but the last\n"
          "                             NUM lines of each file\n"
          "  -q, --quiet, --silent    never print headers giving file names\n"
          "  -v, --verbose            always print headers giving file names\n"
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

static bool headParseCount(const char *s, bool bytes, HeadOptions *o) {
    char q[512];
    const char *p = s;
    bool neg = *p == '-';
    if (neg) p++;
    uintmax_t v;
    int r = gnuParseSize(p, &v);
    if (r == 2) {
        v = UINTMAX_MAX; /* GNU takes a count too large as "all" */
        r = 0;
    }
    if (r != 0) {
        fprintf(stderr, "head: invalid number of %s: %s\n", bytes ? "bytes" : "lines",
                gnuQuoteLocale(s, q, sizeof(q)));
        return false;
    }
    o->bytes = bytes;
    o->allBut = neg;
    o->count = v;
    return true;
}

static int headMissingArg(const char *what) {
    fprintf(stderr, "head: option requires an argument -- '%s'\nTry 'head --help' for more information.\n", what);
    return 1;
}

int smallclueHeadCommand(int argc, char **argv) {
    HeadOptions o = {false, false, 10, '\n', 0};
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nfiles = 0, status = 0;
    if (!files) return 1;

    /* The obsolete form, first argument only: -NUM[bkm|c|l][qvz]. */
    int start = 1;
    if (argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9') {
        char *end;
        errno = 0;
        uintmax_t v = strtoumax(argv[1] + 1, &end, 10);
        bool bytes = false;
        if (*end == 'c') { bytes = true; end++; }
        else if (*end == 'b') { v *= 512; bytes = true; end++; }
        else if (*end == 'k') { v *= 1024; bytes = true; end++; }
        else if (*end == 'm') { v *= 1048576; bytes = true; end++; }
        else if (*end == 'l') { end++; }
        for (; *end; end++) {
            if (*end == 'q') o.headers = -1;
            else if (*end == 'v') o.headers = 1;
            else if (*end == 'z') o.delim = '\0';
            else {
                fprintf(stderr, "head: invalid trailing option -- %c\nTry 'head --help' for more information.\n", *end);
                free(files);
                return 1;
            }
        }
        o.count = v;
        o.bytes = bytes;
        start = 2;
    }

    bool endOfOptions = false;
    for (int i = start; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            files[nfiles++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *val = strchr(opt, '=');
            size_t len = val ? (size_t)(val - opt) : strlen(opt);
            if (val) val++;
            /* Unambiguous prefixes are accepted, as getopt_long does. */
            static const char *const names[] = {"bytes", "lines", "quiet", "silent", "verbose", "zero-terminated", "help", "version"};
            int match = -1, matches = 0;
            for (int k = 0; k < 8; k++) {
                if (!strncmp(names[k], opt, len)) {
                    if (strlen(names[k]) == len) { match = k; matches = 1; break; }
                    match = k;
                    matches++;
                }
            }
            if (matches != 1) {
                fprintf(stderr, "head: %s option '%s'\nTry 'head --help' for more information.\n",
                        matches ? "ambiguous" : "unrecognized", arg);
                status = 1;
                goto done;
            }
            if (match <= 1) {
                if (!val) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "head: option '--%s' requires an argument\nTry 'head --help' for more information.\n", names[match]);
                        status = 1;
                        goto done;
                    }
                    val = argv[++i];
                }
                if (!headParseCount(val, match == 0, &o)) { status = 1; goto done; }
                continue;
            }
            if (val) {
                fprintf(stderr, "head: option '--%s' doesn't allow an argument\nTry 'head --help' for more information.\n", names[match]);
                status = 1;
                goto done;
            }
            if (match == 2 || match == 3) o.headers = -1;
            else if (match == 4) o.headers = 1;
            else if (match == 5) o.delim = '\0';
            else if (match == 6) { headUsage(); goto done; }
            else { puts("head (SmallCLUE) 9.4"); goto done; }
            continue;
        }
        for (const char *c = arg + 1; *c; c++) {
            if (*c == 'c' || *c == 'n') {
                const char *val = c[1] ? c + 1 : NULL;
                if (!val) {
                    if (i + 1 >= argc) { status = headMissingArg(*c == 'c' ? "c" : "n"); goto done; }
                    val = argv[++i];
                }
                if (!headParseCount(val, *c == 'c', &o)) { status = 1; goto done; }
                break;
            }
            if (*c == 'q') o.headers = -1;
            else if (*c == 'v') o.headers = 1;
            else if (*c == 'z') o.delim = '\0';
            else {
                fprintf(stderr, "head: invalid option -- '%c'\nTry 'head --help' for more information.\n", *c);
                status = 1;
                goto done;
            }
        }
    }

    if (nfiles == 0) files[nfiles++] = (char *)"-";
    bool header = o.headers == 1 || (o.headers == 0 && nfiles > 1);
    bool first = true;
    for (int i = 0; i < nfiles; i++)
        if (!headFile(files[i], &o, header, &first, &status)) break;

done:
    if (fflush(stdout) != 0 || ferror(stdout)) {
        if (errno != EPIPE) fprintf(stderr, "head: error writing 'standard output': %s\n", strerror(errno));
        status = 1;
    }
    free(files);
    return status;
}
