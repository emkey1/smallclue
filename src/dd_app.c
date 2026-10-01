/*
 * dd: GNU coreutils 9 compatible. Every operand (if of ibs obs bs cbs skip
 * iseek seek oseek count conv iflag oflag status) with GNU's number syntax
 * (c w b kB K MB M ... and NxM products); conv ascii/ebcdic/ibm (POSIX's
 * tables, as GNU dd has them), block/unblock with truncation counts,
 * lcase/ucase, swab across blocks, sync, sparse, excl, nocreat, notrunc,
 * noerror, fsync, fdatasync; the flags that mean something here (append,
 * fullblock, count_bytes, skip_bytes, seek_bytes, nofollow, directory,
 * nonblock, noctty, sync, dsync; the rest accepted); one buffer when bs=
 * allows it, two otherwise; and GNU's records/bytes report with gnulib's
 * human-readable sizes and rates.
 */

#include "dd_app.h"

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
#include <time.h>
#include <unistd.h>

static const unsigned char dd_ebcdic[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
    0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x9a, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0x5f, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x6a, 0x9b, 0x9c, 0x9d, 0x9e,
    0x9f, 0xa0, 0xaa, 0xab, 0xac, 0x4a, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xa1, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static const unsigned char dd_ibm[256] = {
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
    0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
    0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
    0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
    0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xe1,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x80, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
    0x9f, 0xa0, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static const unsigned char dd_ascii[256] = {
    0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x9d, 0x85, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x0a, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07,
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b, 0x14, 0x15, 0x9e, 0x1a,
    0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xd5, 0x2e, 0x3c, 0x28, 0x2b, 0x7c,
    0x26, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x7e,
    0x2d, 0x2f, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xcb, 0x2c, 0x25, 0x5f, 0x3e, 0x3f,
    0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22,
    0xc3, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
    0xca, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x5e, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
    0xd1, 0xe5, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0xd2, 0xd3, 0xd4, 0x5b, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0x5d, 0xe6, 0xe7,
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
    0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3,
    0x5c, 0x9f, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

enum {
    DDC_ASCII = 1 << 0, DDC_EBCDIC = 1 << 1, DDC_IBM = 1 << 2, DDC_BLOCK = 1 << 3, DDC_UNBLOCK = 1 << 4,
    DDC_LCASE = 1 << 5, DDC_UCASE = 1 << 6, DDC_SWAB = 1 << 7, DDC_SYNC = 1 << 8, DDC_SPARSE = 1 << 9,
    DDC_EXCL = 1 << 10, DDC_NOCREAT = 1 << 11, DDC_NOTRUNC = 1 << 12, DDC_NOERROR = 1 << 13,
    DDC_FSYNC = 1 << 14, DDC_FDATASYNC = 1 << 15, DDC_TWOBUFS = 1 << 16,
};
enum {
    DDF_APPEND = 1 << 0, DDF_FULLBLOCK = 1 << 1, DDF_COUNT_BYTES = 1 << 2, DDF_SKIP_BYTES = 1 << 3,
    DDF_SEEK_BYTES = 1 << 4, DDF_NOFOLLOW = 1 << 5, DDF_DIRECTORY = 1 << 6, DDF_NONBLOCK = 1 << 7,
    DDF_NOCTTY = 1 << 8, DDF_SYNC = 1 << 9, DDF_DSYNC = 1 << 10, DDF_DIRECT = 1 << 11, DDF_NOCACHE = 1 << 12,
    DDF_IGNORED = 1 << 13,
};
enum { DDST_DEFAULT, DDST_NONE, DDST_NOXFER, DDST_PROGRESS };

typedef struct { const char *name; int bits; } DdSym;

static const DdSym ddConvs[] = {
    {"ascii", DDC_ASCII | DDC_UNBLOCK | DDC_TWOBUFS}, {"ebcdic", DDC_EBCDIC | DDC_BLOCK | DDC_TWOBUFS},
    {"ibm", DDC_IBM | DDC_BLOCK | DDC_TWOBUFS},       {"block", DDC_BLOCK | DDC_TWOBUFS},
    {"unblock", DDC_UNBLOCK | DDC_TWOBUFS},         {"lcase", DDC_LCASE | DDC_TWOBUFS},
    {"ucase", DDC_UCASE | DDC_TWOBUFS},             {"sparse", DDC_SPARSE},
    {"swab", DDC_SWAB | DDC_TWOBUFS},               {"noerror", DDC_NOERROR},
    {"nocreat", DDC_NOCREAT},                     {"excl", DDC_EXCL},
    {"notrunc", DDC_NOTRUNC},                     {"sync", DDC_SYNC},
    {"fdatasync", DDC_FDATASYNC},                 {"fsync", DDC_FSYNC},
    {NULL, 0},
};
static const DdSym ddFlags[] = {
    {"append", DDF_APPEND},       {"binary", DDF_IGNORED},        {"count_bytes", DDF_COUNT_BYTES},
    {"direct", DDF_DIRECT},       {"directory", DDF_DIRECTORY},   {"dsync", DDF_DSYNC},
    {"noatime", DDF_IGNORED},     {"nocache", DDF_NOCACHE},       {"noctty", DDF_NOCTTY},
    {"nofollow", DDF_NOFOLLOW},   {"nolinks", DDF_IGNORED},       {"nonblock", DDF_NONBLOCK},
    {"sync", DDF_SYNC},           {"text", DDF_IGNORED},          {"fullblock", DDF_FULLBLOCK},
    {"skip_bytes", DDF_SKIP_BYTES}, {"seek_bytes", DDF_SEEK_BYTES}, {NULL, 0},
};
static const DdSym ddStatus[] = {
    {"none", DDST_NONE}, {"noxfer", DDST_NOXFER}, {"progress", DDST_PROGRESS}, {NULL, 0},
};

typedef struct {
    const char *inName, *outName;
    int ifd, ofd;
    intmax_t ibs, obs, cbs;
    intmax_t skipRecords, skipBytes, seekRecords, seekBytes, maxRecords, maxBytes;
    int conv, iflags, oflags, status;
    bool warnPartial;
    intmax_t prevRead;
    unsigned char trans[256];
    bool translate;
    unsigned char newline, space;
    unsigned char *obuf;
    intmax_t oc, col, pendingSpaces;
    int savedByte;
    intmax_t rFull, rPartial, wFull, wPartial, rTruncate, wBytes;
    bool finalSeek;
    struct timespec start, lastProgress;
    int progressLen;
    int exitStatus;
} Dd;

static int ddTry(void) {
    fputs("Try 'dd --help' for more information.\n", stderr);
    return 1;
}

/* xstrtoumax, base 10, suffixes "bcEGkKMPQRTwYZ0": 0 ok, 1 invalid, 2 overflow,
 * 3 a bad suffix character at *end. */
static int ddUnsigned(const char *s, const char **endp, uintmax_t *out) {
    const char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '-') return 1;
    char *e;
    errno = 0;
    uintmax_t v = strtoumax(s, &e, 10);
    int st = errno == ERANGE ? 2 : 0;
    if (e == s) return 1;
    *endp = e;
    if (!*e) {
        *out = v;
        return st;
    }
    static const char sfx[] = "bcEGkKMPQRTwYZ";
    if (!strchr(sfx, *e)) {
        *out = v;
        return 3;
    }
    uintmax_t mult = 1;
    size_t used = 1;
    unsigned base = 1024;
    if (*e == 'b') mult = 512;
    else if (*e == 'c') mult = 1;
    else if (*e == 'w') mult = 2;
    else {
        if (e[1] == 'i' && e[2] == 'B') used = 3;
        else if (e[1] == 'B' || e[1] == 'D') base = 1000, used = 2;
        static const char pw[] = "KMGTPEZYRQ";
        char up = *e == 'k' ? 'K' : *e;
        const char *pos = strchr(pw, up);
        for (int i = 0; pos && i <= pos - pw; i++) {
            if (mult > UINTMAX_MAX / base) st = 2, mult = UINTMAX_MAX;
            else mult *= base;
        }
    }
    *endp = e + used;
    if (v && mult > UINTMAX_MAX / v) st = 2, v = UINTMAX_MAX;
    else v *= mult;
    *out = v;
    if (**endp) return 3;
    return st;
}

/* GNU's parse_integer: N, or NxM...; 0 ok, 1 invalid, 2 overflow. */
static int ddInteger(const char *s, intmax_t *out) {
    const char *end = s;
    uintmax_t n = UINTMAX_MAX;
    int e = ddUnsigned(s, &end, &n);
    if (e == 3 && *end == 'x' && !(end[-1] == 'B' && strchr(end + 1, 'B'))) {
        intmax_t o;
        int f = ddInteger(end + 1, &o);
        if (f) {
            *out = INTMAX_MAX;
            return f;
        }
        if (n && (uintmax_t)o > INTMAX_MAX / n) {
            *out = INTMAX_MAX;
            return 2;
        }
        *out = (intmax_t)(n * (uintmax_t)o);
        if (*out == 0 && !strncmp(s, "0x", 2))
            fputs("dd: warning: '0x' is a zero multiplier; use '00x' if that is intended\n", stderr);
        return 0;
    }
    if (e == 3) return 1;
    if (e == 0 && n > INTMAX_MAX) e = 2;
    *out = e ? INTMAX_MAX : (intmax_t)n;
    return e;
}

static bool ddSymbols(const char *val, const DdSym *table, const char *what, int *bits) {
    char q[512];
    const char *p = val;
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        const DdSym *s = table;
        for (; s->name; s++)
            if (strlen(s->name) == len && !strncmp(s->name, p, len)) break;
        if (!s->name) {
            char bad[256];
            snprintf(bad, sizeof(bad), "%.*s", (int)len, p);
            fprintf(stderr, "dd: %s: %s\n", what, gnuQuoteLocale(len ? bad : val, q, sizeof(q)));
            return false;
        }
        *bits |= s->bits;
        if (!comma) return true;
        p = comma + 1;
    }
}

/* gnulib human_readable, autoscaled, rounded to nearest: the exact path (a
 * byte count) shows tenths below 10, the inexact one (a rate) below 100
 * and always scales at least once. */
static void ddHuman(char *out, size_t n, long double amt, bool exact, bool si, const char *suffix) {
    static const char *const units[] = {"k", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q"};
    unsigned base = si ? 1000 : 1024;
    int exponent = 0;
    if (exact) {
        while (amt >= base && exponent < 10) {
            amt /= base;
            exponent++;
        }
    } else {
        do {
            amt /= base;
            exponent++;
        } while (amt >= base && exponent < 10);
    }
    char num[64];
    if (exponent == 0) {
        snprintf(num, sizeof(num), "%.0Lf", amt);
    } else {
        snprintf(num, sizeof(num), "%.1Lf", amt);
        if ((exact && amt >= 10 - 0.05) || (!exact && strlen(num) > 4)) snprintf(num, sizeof(num), "%.0Lf", amt);
        if (strtold(num, NULL) >= base && exponent < 10) {
            amt /= base;
            exponent++;
            snprintf(num, sizeof(num), "%.1Lf", amt);
        }
    }
    if (exponent == 0) snprintf(out, n, "%s B%s", num, suffix);
    else if (si) snprintf(out, n, "%s %sB%s", num, exponent == 1 ? "k" : units[exponent - 1], suffix);
    else snprintf(out, n, "%s %siB%s", num, exponent == 1 ? "K" : units[exponent - 1], suffix);
}

static double ddElapsed(const Dd *d, struct timespec *now) {
    clock_gettime(CLOCK_MONOTONIC, now);
    return (double)(now->tv_sec - d->start.tv_sec) + (double)(now->tv_nsec - d->start.tv_nsec) / 1e9;
}

static void ddXfer(Dd *d, bool progress) {
    struct timespec now;
    double secs = ddElapsed(d, &now);
    char si[64], iec[64], rate[64], line[256];
    ddHuman(si, sizeof(si), (long double)d->wBytes, true, true, "");
    ddHuman(iec, sizeof(iec), (long double)d->wBytes, true, false, "");
    if (secs > 0) ddHuman(rate, sizeof(rate), (long double)d->wBytes / secs, false, true, "/s");
    else snprintf(rate, sizeof(rate), "Infinity B/s");
    bool siPlain = strstr(si, " B") && !strstr(si, " kB");
    bool iecPlain = !strchr(iec, 'i');
    int len;
    if (siPlain)
        len = snprintf(line, sizeof(line), d->wBytes == 1 ? "%jd byte copied, %g s, %s" : "%jd bytes copied, %g s, %s",
                       d->wBytes, secs, rate);
    else if (iecPlain)
        len = snprintf(line, sizeof(line), "%jd bytes (%s) copied, %g s, %s", d->wBytes, si, secs, rate);
    else
        len = snprintf(line, sizeof(line), "%jd bytes (%s, %s) copied, %g s, %s", d->wBytes, si, iec, secs, rate);
    if (progress) {
        fprintf(stderr, "\r%s", line);
        for (int k = len; k < d->progressLen; k++) fputc(' ', stderr);
        d->progressLen = len;
    } else {
        if (d->progressLen) fputc('\n', stderr);
        fprintf(stderr, "%s\n", line);
    }
}

static void ddStats(Dd *d) {
    if (d->status == DDST_NONE) return;
    if (d->progressLen) {
        fputc('\n', stderr);
        d->progressLen = 0;
    }
    fprintf(stderr, "%jd+%jd records in\n%jd+%jd records out\n", d->rFull, d->rPartial, d->wFull, d->wPartial);
    if (d->rTruncate)
        fprintf(stderr, d->rTruncate == 1 ? "%jd truncated record\n" : "%jd truncated records\n", d->rTruncate);
    if (d->status == DDST_NOXFER) return;
    ddXfer(d, false);
}

static intmax_t ddWriteAll(int fd, const unsigned char *b, intmax_t n) {
    intmax_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, b + done, (size_t)(n - done));
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (w == 0) {
            errno = ENOSPC;
            break;
        }
        done += w;
    }
    return done;
}

/* One output block; false after an error. With conv=sparse an all-zero
 * block on a seekable output is a seek. */
static bool ddWriteOut(Dd *d) {
    char q[4096];
    if (d->conv & DDC_SPARSE) {
        bool zero = true;
        for (intmax_t i = 0; i < d->obs && zero; i++) zero = !d->obuf[i];
        if (zero && lseek(d->ofd, (off_t)d->obs, SEEK_CUR) >= 0) {
            d->wBytes += d->obs;
            d->wFull++;
            d->oc = 0;
            d->finalSeek = true;
            return true;
        }
    }
    intmax_t w = ddWriteAll(d->ofd, d->obuf, d->obs);
    d->wBytes += w;
    if (w != d->obs) {
        fprintf(stderr, "dd: error writing %s: %s\n", gnuQuote(d->outName, q, sizeof(q)), strerror(errno));
        return false;
    }
    d->finalSeek = false;
    d->wFull++;
    d->oc = 0;
    return true;
}

static bool ddPut(Dd *d, unsigned char c) {
    d->obuf[d->oc++] = c;
    return d->oc < d->obs || ddWriteOut(d);
}

static bool ddCopySimple(Dd *d, const unsigned char *b, intmax_t n) {
    while (n) {
        intmax_t free = d->obs - d->oc < n ? d->obs - d->oc : n;
        memcpy(d->obuf + d->oc, b, (size_t)free);
        n -= free;
        b += free;
        d->oc += free;
        if (d->oc >= d->obs && !ddWriteOut(d)) return false;
    }
    return true;
}

static bool ddCopyBlock(Dd *d, const unsigned char *b, intmax_t n) {
    for (; n; n--, b++) {
        if (*b == d->newline) {
            for (intmax_t j = d->col; j < d->cbs; j++)
                if (!ddPut(d, d->space)) return false;
            d->col = 0;
        } else {
            if (d->col == d->cbs) d->rTruncate++;
            else if (d->col < d->cbs && !ddPut(d, *b)) return false;
            d->col++;
        }
    }
    return true;
}

static bool ddCopyUnblock(Dd *d, const unsigned char *b, intmax_t n) {
    for (intmax_t i = 0; i < n; i++) {
        unsigned char c = b[i];
        if (d->col++ >= d->cbs) {
            d->col = d->pendingSpaces = 0;
            i--;
            if (!ddPut(d, d->newline)) return false;
        } else if (c == d->space) {
            d->pendingSpaces++;
        } else {
            for (; d->pendingSpaces; d->pendingSpaces--)
                if (!ddPut(d, d->space)) return false;
            if (!ddPut(d, c)) return false;
        }
    }
    return true;
}

static bool ddConvert(Dd *d, const unsigned char *b, intmax_t n) {
    if (d->conv & DDC_BLOCK) return ddCopyBlock(d, b, n);
    if (d->conv & DDC_UNBLOCK) return ddCopyUnblock(d, b, n);
    return ddCopySimple(d, b, n);
}

/* A read, whole blocks with iflag=fullblock; GNU's partial-read warning. */
static intmax_t ddRead(Dd *d, unsigned char *b, intmax_t size) {
    intmax_t got = 0;
    for (;;) {
        ssize_t r = read(d->ifd, b + got, (size_t)(size - got));
        if (r < 0) {
            if (errno == EINTR) continue;
            return got ? got : -1;
        }
        if (r > 0 && d->warnPartial) {
            if (d->prevRead > 0 && d->prevRead < size) {
                if (d->status != DDST_NONE)
                    fprintf(stderr, d->prevRead == 1 ? "dd: warning: partial read (%jd byte); suggest iflag=fullblock\n"
                                                     : "dd: warning: partial read (%jd bytes); suggest iflag=fullblock\n",
                            d->prevRead);
                d->warnPartial = false;
            }
        }
        d->prevRead = r;
        got += r;
        if (r == 0 || !(d->iflags & DDF_FULLBLOCK) || got == size) return got;
    }
}

/* GNU's skip(): seek, else read (input) -- what was not skipped is left in
 * records and bytes. False when the output cannot seek. */
static bool ddSkip(Dd *d, int fd, bool input, intmax_t *records, intmax_t blocksize, intmax_t *bytes) {
    char q[4096];
    off_t offset = (off_t)(*records * blocksize + *bytes);
    struct stat st;
    if (input && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        off_t at = lseek(fd, 0, SEEK_CUR);
        if (at >= 0 && st.st_size - at < offset) {
            *records = (offset - (st.st_size - at)) / blocksize;
            offset = st.st_size - at;
            *bytes = 0;
        } else {
            *records = 0;
            *bytes = 0;
        }
        if (lseek(fd, offset, SEEK_CUR) >= 0) return true;
    } else if (lseek(fd, offset, SEEK_CUR) >= 0) {
        *records = 0;
        *bytes = 0;
        return true;
    }
    if (!input) {
        fprintf(stderr, "dd: %s: cannot seek: %s\n", gnuQuoteMaybe(d->outName, q, sizeof(q)), strerror(errno));
        return false;
    }
    unsigned char *buf = (unsigned char *)malloc((size_t)(blocksize > *bytes ? blocksize : *bytes) + 1);
    if (!buf) return true;
    while (*records || *bytes) {
        intmax_t want = *records ? blocksize : *bytes;
        intmax_t r = ddRead(d, buf, want);
        if (r < 0) {
            fprintf(stderr, "dd: error reading %s: %s\n", gnuQuote(d->inName, q, sizeof(q)), strerror(errno));
            break;
        }
        if (r == 0) break;
        if (*records) (*records)--;
        else *bytes = 0;
    }
    free(buf);
    return true;
}

static bool ddSwab(Dd *d, unsigned char *work, const unsigned char *b, intmax_t *n) {
    intmax_t len = 0;
    if (d->savedByte >= 0) work[len++] = (unsigned char)d->savedByte;
    memcpy(work + len, b, (size_t)*n);
    len += *n;
    intmax_t pairs = len / 2 * 2;
    for (intmax_t i = 0; i < pairs; i += 2) {
        unsigned char t = work[i];
        work[i] = work[i + 1];
        work[i + 1] = t;
    }
    d->savedByte = len > pairs ? work[len - 1] : -1;
    *n = pairs;
    return true;
}

static int ddOpenFlags(int f) {
    int o = 0;
    if (f & DDF_APPEND) o |= O_APPEND;
    if (f & DDF_NOFOLLOW) o |= O_NOFOLLOW;
    if (f & DDF_DIRECTORY) o |= O_DIRECTORY;
    if (f & DDF_NONBLOCK) o |= O_NONBLOCK;
    if (f & DDF_NOCTTY) o |= O_NOCTTY;
    if (f & DDF_SYNC) o |= O_SYNC;
#ifdef O_DSYNC
    if (f & DDF_DSYNC) o |= O_DSYNC;
#endif
    return o;
}

int smallclueDdCommand(int argc, char **argv) {
    Dd d;
    memset(&d, 0, sizeof(d));
    d.inName = "standard input";
    d.outName = "standard output";
    d.ifd = STDIN_FILENO;
    d.ofd = STDOUT_FILENO;
    d.savedByte = -1;
    d.newline = '\n';
    d.space = ' ';
    const char *inPath = NULL, *outPath = NULL;
    intmax_t bs = 0, skip = 0, seek = 0, count = INTMAX_MAX;
    char q[4096];
    int status = 1;
    unsigned char *ibuf = NULL, *work = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help")) {
            fputs("Usage: dd [OPERAND]...\n"
                  "  or:  dd OPTION\n"
                  "Copy a file, converting and formatting according to the operands.\n\n"
                  "  bs=BYTES        read and write up to BYTES bytes at a time (default: 512);\n"
                  "                  overrides ibs and obs\n"
                  "  cbs=BYTES       convert BYTES bytes at a time\n"
                  "  conv=CONVS      convert the file as per the comma separated symbol list\n"
                  "  count=N         copy only N input blocks\n"
                  "  ibs=BYTES       read up to BYTES bytes at a time (default: 512)\n"
                  "  if=FILE         read from FILE instead of stdin\n"
                  "  iflag=FLAGS     read as per the comma separated symbol list\n"
                  "  obs=BYTES       write BYTES bytes at a time (default: 512)\n"
                  "  of=FILE         write to FILE instead of stdout\n"
                  "  oflag=FLAGS     write as per the comma separated symbol list\n"
                  "  seek=N          (or oseek=N) skip N obs-sized output blocks\n"
                  "  skip=N          (or iseek=N) skip N ibs-sized input blocks\n"
                  "  status=LEVEL    The LEVEL of information to print to stderr;\n"
                  "                  'none', 'noxfer' or 'progress'\n",
                  stdout);
            return 0;
        }
        if (!strcmp(a, "--version")) {
            puts("dd (SmallCLUE) 9.4");
            return 0;
        }
        if (a[0] == '-' && a[1]) {
            if (a[1] == '-') fprintf(stderr, "dd: unrecognized option '%s'\n", a);
            else fprintf(stderr, "dd: invalid option -- '%c'\n", a[1]);
            return ddTry();
        }
        const char *eq = strchr(a, '=');
        if (!eq) {
            fprintf(stderr, "dd: unrecognized operand %s\n", gnuQuote(a, q, sizeof(q)));
            return ddTry();
        }
        size_t nl = (size_t)(eq - a);
        const char *val = eq + 1;
#define DD_IS(name) (nl == strlen(name) && !strncmp(a, name, nl))
        if (DD_IS("if")) inPath = val;
        else if (DD_IS("of")) outPath = val;
        else if (DD_IS("conv")) { if (!ddSymbols(val, ddConvs, "invalid conversion", &d.conv)) return ddTry(); }
        else if (DD_IS("iflag")) { if (!ddSymbols(val, ddFlags, "invalid input flag", &d.iflags)) return ddTry(); }
        else if (DD_IS("oflag")) { if (!ddSymbols(val, ddFlags, "invalid output flag", &d.oflags)) return ddTry(); }
        else if (DD_IS("status")) {
            d.status = DDST_DEFAULT;
            int st = 0;
            if (!ddSymbols(val, ddStatus, "invalid status level", &st)) return ddTry();
            d.status = st;
        } else if (DD_IS("bs") || DD_IS("ibs") || DD_IS("obs") || DD_IS("cbs") || DD_IS("skip") || DD_IS("iseek") ||
                   DD_IS("seek") || DD_IS("oseek") || DD_IS("count")) {
            intmax_t n;
            int e = ddInteger(val, &n);
            bool block = DD_IS("bs") || DD_IS("ibs") || DD_IS("obs") || DD_IS("cbs");
            if (!e && block && n == 0) e = 1;
            if (e) {
                if (e == 2) fprintf(stderr, "dd: invalid number: %s: Value too large for defined data type\n",
                                    gnuQuote(val, q, sizeof(q)));
                else fprintf(stderr, "dd: invalid number: %s\n", gnuQuote(val, q, sizeof(q)));
                return 1;
            }
            if (DD_IS("bs")) bs = n;
            else if (DD_IS("ibs")) d.ibs = n;
            else if (DD_IS("obs")) d.obs = n;
            else if (DD_IS("cbs")) d.cbs = n;
            else if (DD_IS("skip") || DD_IS("iseek")) skip = n;
            else if (DD_IS("seek") || DD_IS("oseek")) seek = n;
            else count = n;
        } else {
            fprintf(stderr, "dd: unrecognized operand %s\n", gnuQuote(a, q, sizeof(q)));
            return ddTry();
        }
#undef DD_IS
    }
    /* scanargs' order */
    /* POSIX: without bs=, partial reads are gathered into obs-sized blocks */
    if (bs) d.ibs = d.obs = bs;
    else d.conv |= DDC_TWOBUFS;
    if (!d.ibs) d.ibs = 512;
    if (!d.obs) d.obs = 512;
    if (!d.cbs) d.conv &= ~(DDC_BLOCK | DDC_UNBLOCK);
    if (d.oflags & DDF_FULLBLOCK) {
        fprintf(stderr, "dd: invalid output flag: %s\n", gnuQuoteLocale("fullblock", q, sizeof(q)));
        return ddTry();
    }
    if (d.oflags & (DDF_COUNT_BYTES | DDF_SKIP_BYTES)) {
        fprintf(stderr, "dd: invalid output flag: %s\n",
                gnuQuoteLocale(d.oflags & DDF_COUNT_BYTES ? "count_bytes" : "skip_bytes", q, sizeof(q)));
        return ddTry();
    }
    if ((d.iflags & DDF_SKIP_BYTES) && skip) d.skipRecords = skip / d.ibs, d.skipBytes = skip % d.ibs;
    else d.skipRecords = skip;
    if ((d.iflags & DDF_COUNT_BYTES) && count != INTMAX_MAX) d.maxRecords = count / d.ibs, d.maxBytes = count % d.ibs;
    else d.maxRecords = count;
    if ((d.oflags & DDF_SEEK_BYTES) && seek) d.seekRecords = seek / d.obs, d.seekBytes = seek % d.obs;
    else d.seekRecords = seek;
    d.warnPartial = !(d.conv & DDC_TWOBUFS) && !(d.iflags & DDF_FULLBLOCK) &&
                    (d.skipRecords || (0 < d.maxRecords && d.maxRecords < INTMAX_MAX) ||
                     ((d.iflags | d.oflags) & DDF_DIRECT));
    int ce = d.conv & (DDC_ASCII | DDC_EBCDIC | DDC_IBM);
    if (ce & (ce - 1)) { fputs("dd: cannot combine any two of {ascii,ebcdic,ibm}\n", stderr); return 1; }
    if ((d.conv & DDC_BLOCK) && (d.conv & DDC_UNBLOCK)) { fputs("dd: cannot combine block and unblock\n", stderr); return 1; }
    if ((d.conv & DDC_LCASE) && (d.conv & DDC_UCASE)) { fputs("dd: cannot combine lcase and ucase\n", stderr); return 1; }
    if ((d.conv & DDC_EXCL) && (d.conv & DDC_NOCREAT)) { fputs("dd: cannot combine excl and nocreat\n", stderr); return 1; }
    if (((d.iflags & DDF_DIRECT) && (d.iflags & DDF_NOCACHE)) || ((d.oflags & DDF_DIRECT) && (d.oflags & DDF_NOCACHE))) {
        fputs("dd: cannot combine direct and nocache\n", stderr);
        return 1;
    }
    /* apply_translations */
    for (int k = 0; k < 256; k++) d.trans[k] = (unsigned char)k;
    if (d.conv & DDC_ASCII) {
        for (int k = 0; k < 256; k++) d.trans[k] = dd_ascii[d.trans[k]];
        d.translate = true;
    }
    if (d.conv & (DDC_UCASE | DDC_LCASE)) {
        for (int k = 0; k < 256; k++) {
            int c = d.trans[k];
            if ((d.conv & DDC_UCASE) && c >= 'a' && c <= 'z') d.trans[k] = (unsigned char)(c - 32);
            if ((d.conv & DDC_LCASE) && c >= 'A' && c <= 'Z') d.trans[k] = (unsigned char)(c + 32);
        }
        d.translate = true;
    }
    if (d.conv & (DDC_EBCDIC | DDC_IBM)) {
        const unsigned char *t = d.conv & DDC_EBCDIC ? dd_ebcdic : dd_ibm;
        for (int k = 0; k < 256; k++) d.trans[k] = t[d.trans[k]];
        d.newline = t['\n'];
        d.space = t[' '];
        d.translate = true;
    }
    if (inPath) {
        d.inName = inPath;
        d.ifd = open(inPath, O_RDONLY | ddOpenFlags(d.iflags));
        if (d.ifd < 0) {
            fprintf(stderr, "dd: failed to open %s: %s\n", gnuQuote(inPath, q, sizeof(q)), strerror(errno));
            return 1;
        }
    }
    if (outPath) {
        d.outName = outPath;
        int opts = ddOpenFlags(d.oflags) | (d.conv & DDC_NOCREAT ? 0 : O_CREAT) | (d.conv & DDC_EXCL ? O_EXCL : 0) |
                   (d.seekRecords || (d.conv & DDC_NOTRUNC) ? 0 : O_TRUNC);
        d.ofd = -1;
        if (d.seekRecords) d.ofd = open(outPath, O_RDWR | opts, 0666);
        if (d.ofd < 0) d.ofd = open(outPath, O_WRONLY | opts, 0666);
        if (d.ofd < 0) {
            fprintf(stderr, "dd: failed to open %s: %s\n", gnuQuote(outPath, q, sizeof(q)), strerror(errno));
            goto out;
        }
        if (d.seekRecords && !(d.conv & DDC_NOTRUNC)) {
            off_t size = (off_t)(d.seekRecords * d.obs + d.seekBytes);
            struct stat st;
            if (ftruncate(d.ofd, size) != 0 && fstat(d.ofd, &st) == 0 && S_ISREG(st.st_mode)) {
                fprintf(stderr, "dd: failed to truncate to %jd bytes in output file %s: %s\n", (intmax_t)size,
                        gnuQuote(outPath, q, sizeof(q)), strerror(errno));
                goto out;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &d.start);
    d.lastProgress = d.start;
    d.exitStatus = 0;
    /* dd_copy */
    if (d.skipRecords || d.skipBytes) {
        intmax_t recs = d.skipRecords, bytes = d.skipBytes;
        ddSkip(&d, d.ifd, true, &recs, d.ibs, &bytes);
        if (recs || bytes) fprintf(stderr, "dd: %s: cannot skip to specified offset\n", gnuQuoteMaybe(d.inName, q, sizeof(q)));
    }
    if (d.seekRecords || d.seekBytes) {
        intmax_t recs = d.seekRecords, bytes = d.seekBytes;
        if (!ddSkip(&d, d.ofd, false, &recs, d.obs, &bytes)) {
            d.exitStatus = 1;
            goto finish_quiet;
        }
    }
    if (d.maxRecords == 0 && d.maxBytes == 0) goto finish;
    ibuf = (unsigned char *)malloc((size_t)d.ibs + 1);
    work = (unsigned char *)malloc((size_t)d.ibs + 2);
    d.obuf = d.conv & DDC_TWOBUFS ? (unsigned char *)malloc((size_t)d.obs) : ibuf;
    if (!ibuf || !work || !d.obuf) {
        fputs("dd: memory exhausted\n", stderr);
        d.exitStatus = 1;
        goto finish;
    }
    intmax_t partread = 0;
    for (;;) {
        if (d.rPartial + d.rFull >= d.maxRecords + (d.maxBytes ? 1 : 0)) break;
        if (d.status == DDST_PROGRESS) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > d.lastProgress.tv_sec) {
                d.lastProgress = now;
                ddXfer(&d, true);
            }
        }
        if ((d.conv & DDC_SYNC) && (d.conv & DDC_NOERROR))
            memset(ibuf, (d.conv & (DDC_BLOCK | DDC_UNBLOCK)) ? ' ' : '\0', (size_t)d.ibs);
        intmax_t want = d.rPartial + d.rFull >= d.maxRecords ? d.maxBytes : d.ibs;
        intmax_t nread = ddRead(&d, ibuf, want);
        if (nread == 0) break;
        if (nread < 0) {
            fprintf(stderr, "dd: error reading %s: %s\n", gnuQuote(d.inName, q, sizeof(q)), strerror(errno));
            if (d.conv & DDC_NOERROR) {
                ddStats(&d);
                lseek(d.ifd, (off_t)(d.ibs - partread), SEEK_CUR);
                d.exitStatus = 1;
                if ((d.conv & DDC_SYNC) && !partread) nread = 0;
                else continue;
            } else {
                d.exitStatus = 1;
                break;
            }
        }
        intmax_t n = nread;
        if (n < d.ibs) {
            d.rPartial++;
            partread = n;
            if (d.conv & DDC_SYNC) {
                if (!(d.conv & DDC_NOERROR))
                    memset(ibuf + n, (d.conv & (DDC_BLOCK | DDC_UNBLOCK)) ? ' ' : '\0', (size_t)(d.ibs - n));
                n = d.ibs;
            }
        } else {
            d.rFull++;
            partread = 0;
        }
        if (ibuf == d.obuf) {
            intmax_t w = ddWriteAll(d.ofd, ibuf, n);
            d.wBytes += w;
            if (w != n) {
                fprintf(stderr, "dd: error writing %s: %s\n", gnuQuote(d.outName, q, sizeof(q)), strerror(errno));
                d.exitStatus = 1;
                goto finish;
            }
            if (n == d.ibs) d.wFull++;
            else d.wPartial++;
            continue;
        }
        if (d.translate)
            for (intmax_t k = 0; k < n; k++) ibuf[k] = d.trans[ibuf[k]];
        const unsigned char *start = ibuf;
        if (d.conv & DDC_SWAB) {
            ddSwab(&d, work, ibuf, &n);
            start = work;
        }
        if (!ddConvert(&d, start, n)) {
            d.exitStatus = 1;
            goto finish;
        }
    }
    if (d.savedByte >= 0) {
        unsigned char c = (unsigned char)d.savedByte;
        if (!ddConvert(&d, &c, 1)) {
            d.exitStatus = 1;
            goto finish;
        }
    }
    if ((d.conv & DDC_BLOCK) && d.col > 0)
        for (intmax_t k = d.col; k < d.cbs; k++)
            if (!ddPut(&d, d.space)) {
                d.exitStatus = 1;
                goto finish;
            }
    if (d.col && (d.conv & DDC_UNBLOCK) && !ddPut(&d, d.newline)) {
        d.exitStatus = 1;
        goto finish;
    }
    if (d.oc) {
        intmax_t w = ddWriteAll(d.ofd, d.obuf, d.oc);
        d.wBytes += w;
        if (w) d.wPartial++;
        if (w != d.oc) {
            fprintf(stderr, "dd: error writing %s: %s\n", gnuQuote(d.outName, q, sizeof(q)), strerror(errno));
            d.exitStatus = 1;
            goto finish;
        }
        d.finalSeek = false;
    }
    if (d.finalSeek) {
        struct stat st;
        off_t at = lseek(d.ofd, 0, SEEK_CUR);
        if (at >= 0 && fstat(d.ofd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size < at) {
            if (ftruncate(d.ofd, at) != 0) {
                fprintf(stderr, "dd: failed to truncate to %jd bytes in output file %s: %s\n", (intmax_t)at,
                        gnuQuote(d.outName, q, sizeof(q)), strerror(errno));
                d.exitStatus = 1;
            }
        }
    }
    if ((d.conv & (DDC_FSYNC | DDC_FDATASYNC)) && fsync(d.ofd) != 0 && errno != EINVAL && errno != ENOTSUP) {
        fprintf(stderr, "dd: %s failed for %s: %s\n", d.conv & DDC_FSYNC ? "fsync" : "fdatasync",
                gnuQuote(d.outName, q, sizeof(q)), strerror(errno));
        d.exitStatus = 1;
    }
finish:
    ddStats(&d);
finish_quiet:
    status = d.exitStatus;
out:
    if (d.obuf != ibuf) free(d.obuf);
    free(ibuf);
    free(work);
    if (inPath && d.ifd >= 0) close(d.ifd);
    if (outPath && d.ofd >= 0 && close(d.ofd) != 0 && status == 0) {
        fprintf(stderr, "dd: closing output file %s: %s\n", gnuQuote(d.outName, q, sizeof(q)), strerror(errno));
        status = 1;
    }
    return status;
}
