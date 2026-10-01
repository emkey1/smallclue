/*
 * od: GNU coreutils 9 compatible. -t a c d[N] o[N] u[N] x[N] f[N] (with
 * C S I L / F D L sizes) and the z trailer, several formats aligned by
 * GNU's pad distribution, the old -a -b -c -d -f -h -i -l -o -s -x, -A
 * d o x n, -j, -N, -w (GNU's width rule and warning), -v and the "*" line
 * for repeats, -S strings, --endian, the traditional [+]OFFSET operand,
 * floats in their shortest round-trip form (gnulib ftoastr), files read as
 * one stream.
 */

#include "od_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { OD_SIGNED, OD_UNSIGNED, OD_OCTAL, OD_HEX, OD_FLOAT, OD_NAMED, OD_CHAR };

typedef struct {
    int kind, size, width;
    bool trailer;
    intmax_t pad;
} OdSpec;

typedef struct {
    OdSpec specs[64];
    int nspecs;
    int radix;            /* 'o' 'd' 'x' 'n' */
    intmax_t skip, limit; /* limit -1: none */
    intmax_t perLine;
    bool verbose, bigEndian, haveWidth;
    int stringMin;        /* -S: 0 off */
    char **files;
    int nfiles, fileIdx;
    bool opened;          /* some input opened */
    FILE *in;
    const char *inName;
    int status;
} Od;

static int odTry(void) {
    fputs("Try 'od --help' for more information.\n", stderr);
    return 1;
}

static int odDigits(int kind, int size) {
    static const int sdec[9] = {1, 4, 6, 8, 11, 13, 16, 18, 20};
    static const int udec[9] = {0, 3, 5, 8, 10, 13, 15, 17, 20};
    static const int oct[9] = {0, 3, 6, 8, 11, 14, 16, 19, 22};
    switch (kind) {
    case OD_SIGNED: return sdec[size];
    case OD_UNSIGNED: return udec[size];
    case OD_OCTAL: return oct[size];
    case OD_HEX: return size * 2;
    case OD_FLOAT: return size == 4 ? 15 : 24;
    default: return 3;
    }
}

/* -t TYPE...; false after the message. */
static bool odAddType(Od *od, const char *spec) {
    char q[512];
    const char *s = spec;
    while (*s) {
        if (od->nspecs == 64) return false;
        OdSpec *t = &od->specs[od->nspecs];
        memset(t, 0, sizeof(*t));
        char c = *s++;
        switch (c) {
        case 'a': t->kind = OD_NAMED; t->size = 1; break;
        case 'c': t->kind = OD_CHAR; t->size = 1; break;
        case 'd': case 'o': case 'u': case 'x': {
            t->kind = c == 'd' ? OD_SIGNED : c == 'u' ? OD_UNSIGNED : c == 'o' ? OD_OCTAL : OD_HEX;
            t->size = 4;
            if (*s == 'C') t->size = 1, s++;
            else if (*s == 'S') t->size = 2, s++;
            else if (*s == 'I') t->size = 4, s++;
            else if (*s == 'L') t->size = 8, s++;
            else if (isdigit((unsigned char)*s)) {
                char *end;
                long n = strtol(s, &end, 10);
                if (n != 1 && n != 2 && n != 4 && n != 8) {
                    fprintf(stderr, "od: invalid type string %s;\nthis system doesn't provide a %ld-byte integral type\n",
                            gnuQuoteLocale(spec, q, sizeof(q)), n);
                    return false;
                }
                t->size = (int)n;
                s = end;
            }
            break;
        }
        case 'f':
            t->kind = OD_FLOAT;
            t->size = 8;
            if (*s == 'F') t->size = 4, s++;
            else if (*s == 'D' || *s == 'L') t->size = 8, s++;
            else if (isdigit((unsigned char)*s)) {
                char *end;
                long n = strtol(s, &end, 10);
                if (n != 4 && n != 8) {
                    fprintf(stderr, "od: invalid type string %s;\nthis system doesn't provide a %ld-byte floating point type\n",
                            gnuQuoteLocale(spec, q, sizeof(q)), n);
                    return false;
                }
                t->size = (int)n;
                s = end;
            }
            break;
        default:
            fprintf(stderr, "od: invalid character '%c' in type string %s\n", c, gnuQuoteLocale(spec, q, sizeof(q)));
            return false;
        }
        t->width = odDigits(t->kind, t->size);
        if (*s == 'z') t->trailer = true, s++;
        od->nspecs++;
    }
    return true;
}

/* xstrtoumax, base 0, suffixes "bEGKkMmPQRTYZ0" (b 512, k K 1024, m M 1024^2). */
static int odNumber(const char *s, intmax_t *out) {
    char *end;
    errno = 0;
    if (*s == '-') return 1;
    uintmax_t v = strtoumax(s, &end, 0);
    if (end == s) return 1;
    bool ovf = errno == ERANGE;
    if (*end) {
        uintmax_t mult = 1;
        unsigned base = 1024;
        size_t used = 1;
        char u = *end;
        if (u == 'b') mult = 512;
        else {
            if (end[1] == 'i' && end[2] == 'B') used = 3;
            else if (end[1] == 'B' || end[1] == 'D') base = 1000, used = 2;
            static const char pw[] = "KMGTPEZYRQ";
            char up = u == 'k' ? 'K' : u == 'm' ? 'M' : u;
            const char *pos = strchr(pw, up);
            if (!pos) return 1;
            for (int i = 0; i <= pos - pw; i++) {
                if (mult > UINTMAX_MAX / base) ovf = true;
                else mult *= base;
            }
        }
        if (end[used]) return 1;
        if (v && mult > UINTMAX_MAX / v) ovf = true;
        else v *= mult;
    }
    if (ovf || v > INTMAX_MAX) return 2;
    *out = (intmax_t)v;
    return 0;
}

/* parse_old_offset: [+]N[.][b], octal unless "." makes it decimal; 0x hex. */
static bool odOldOffset(const char *s, intmax_t *out) {
    if (*s == '+') s++;
    if (!*s) return false;
    int base = 8;
    size_t len = strlen(s);
    char buf[128];
    if (len >= sizeof(buf)) return false;
    memcpy(buf, s, len + 1);
    bool blocks = false;
    if (len && buf[len - 1] == 'b' && !(len > 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X'))) {
        blocks = true;
        buf[--len] = '\0';
    }
    if (len && buf[len - 1] == '.') {
        base = 10;
        buf[--len] = '\0';
    }
    if (!len) return false;
    char *end;
    errno = 0;
    uintmax_t v = (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) ? strtoumax(buf, &end, 16) : strtoumax(buf, &end, base);
    if (*end || errno) return false;
    if (blocks) v *= 512;
    *out = (intmax_t)v;
    return true;
}

/* The next byte of the combined input, -1 at the end of it. */
static int odGetc(Od *od) {
    char q[4096];
    for (;;) {
        if (!od->in) {
            if (od->fileIdx >= od->nfiles) return -1;
            od->inName = od->files[od->fileIdx++];
            if (!strcmp(od->inName, "-")) {
                od->in = stdin;
            } else if (!(od->in = smallclueAppOpenRead(od->inName))) {
                fprintf(stderr, "od: %s: %s\n", gnuQuoteMaybe(od->inName, q, sizeof(q)), strerror(errno));
                od->status = 1;
                continue;
            }
            od->opened = true;
        }
        int c = getc(od->in);
        if (c != EOF) return c;
        if (ferror(od->in)) {
            fprintf(stderr, "od: %s: read error: %s\n", gnuQuoteMaybe(od->inName, q, sizeof(q)), strerror(errno));
            od->status = 1;
        }
        if (od->in == stdin) clearerr(stdin);
        else fclose(od->in);
        od->in = NULL;
    }
}

static void odAddress(const Od *od, intmax_t a) {
    switch (od->radix) {
    case 'd': printf("%07jd", a); break;
    case 'x': printf("%06jx", a); break;
    case 'n': break;
    default: printf("%07jo", a); break;
    }
}

static int odAddressWidth(const Od *od) {
    return od->radix == 'n' ? 0 : od->radix == 'x' ? 6 : 7;
}

static uintmax_t odElement(const Od *od, const unsigned char *p, int size) {
    uintmax_t v = 0;
    for (int i = 0; i < size; i++) {
        int k = od->bigEndian ? i : size - 1 - i;
        v = (v << 8) | p[k];
    }
    return v;
}

/* gnulib ftoastr: the shortest %g that reads back as the same value. */
static void odFloat(char *buf, size_t n, const unsigned char *p, int size, bool big) {
    unsigned char b[8];
    for (int i = 0; i < size; i++) b[i] = p[big ? size - 1 - i : i];
    if (size == 4) {
        float x;
        memcpy(&x, b, 4);
        for (int prec = fabsf(x) < FLT_MIN ? 1 : FLT_DIG;; prec++) {
            snprintf(buf, n, "%.*g", prec, (double)x);
            if (prec >= 9 || strtof(buf, NULL) == x) break;
        }
    } else {
        double x;
        memcpy(&x, b, 8);
        for (int prec = fabs(x) < DBL_MIN ? 1 : DBL_DIG;; prec++) {
            snprintf(buf, n, "%.*g", prec, x);
            if (prec >= 17 || strtod(buf, NULL) == x) break;
        }
    }
}

static void odField(const Od *od, const OdSpec *t, const unsigned char *p, int width) {
    static const char *const names[] = {"nul", "soh", "stx", "etx", "eot", "enq", "ack", "bel", "bs", "ht", "nl",
                                        "vt",  "ff",  "cr",  "so",  "si",  "dle", "dc1", "dc2", "dc3", "dc4", "nak",
                                        "syn", "etb", "can", "em",  "sub", "esc", "fs",  "gs",  "rs",  "us",  "sp"};
    char buf[64];
    switch (t->kind) {
    case OD_SIGNED: {
        uintmax_t v = odElement(od, p, t->size);
        intmax_t sv;
        if (t->size == 8) sv = (intmax_t)v;
        else {
            uintmax_t sign = (uintmax_t)1 << (t->size * 8 - 1);
            sv = (v & sign) ? (intmax_t)(v - (sign << 1)) : (intmax_t)v;
        }
        printf("%*jd", width, sv);
        break;
    }
    case OD_UNSIGNED: printf("%*ju", width, odElement(od, p, t->size)); break;
    case OD_OCTAL: printf("%*.*jo", width, t->width, odElement(od, p, t->size)); break;
    case OD_HEX: printf("%*.*jx", width, t->width, odElement(od, p, t->size)); break;
    case OD_FLOAT:
        odFloat(buf, sizeof(buf), p, t->size, od->bigEndian);
        printf("%*s", width, buf);
        break;
    case OD_NAMED: {
        int c = *p & 0x7f;
        printf("%*s", width, c == 0x7f ? "del" : c <= 32 ? names[c] : (snprintf(buf, sizeof(buf), "%c", c), buf));
        break;
    }
    default: {
        int c = *p;
        const char *s = NULL;
        switch (c) {
        case 0: s = "\\0"; break;
        case '\a': s = "\\a"; break;
        case '\b': s = "\\b"; break;
        case '\f': s = "\\f"; break;
        case '\n': s = "\\n"; break;
        case '\r': s = "\\r"; break;
        case '\t': s = "\\t"; break;
        case '\v': s = "\\v"; break;
        }
        if (!s) {
            if (c >= 32 && c < 127) snprintf(buf, sizeof(buf), "%c", c);
            else snprintf(buf, sizeof(buf), "%03o", c);
            s = buf;
        }
        printf("%*s", width, s);
        break;
    }
    }
}

/* One line: n bytes of the block (zero-filled to bytes-per-line). */
static void odLine(Od *od, intmax_t addr, const unsigned char *block, intmax_t n) {
    for (int i = 0; i < od->nspecs; i++) {
        const OdSpec *t = &od->specs[i];
        if (i == 0) odAddress(od, addr);
        else printf("%*s", odAddressWidth(od), "");
        intmax_t fields = od->perLine / t->size;
        intmax_t blank = (od->perLine - n) / t->size;
        intmax_t padRemaining = t->pad;
        const unsigned char *p = block;
        for (intmax_t f = fields; blank < f; f--) {
            intmax_t nextPad = t->pad * (f - 1) / fields;
            int width = (int)(padRemaining - nextPad + t->width);
            odField(od, t, p, width);
            p += t->size;
            padRemaining = nextPad;
        }
        if (t->trailer) {
            printf("%*s", (int)(blank * (t->width + 1)), "");
            fputs("  >", stdout);
            for (intmax_t k = 0; k < n; k++) putchar(isprint(block[k]) && block[k] < 127 ? block[k] : '.');
            putchar('<');
        }
        putchar('\n');
    }
}

static void odStrings(Od *od, intmax_t addr) {
    size_t cap = 256, len = 0;
    char *s = (char *)malloc(cap);
    intmax_t start = addr;
    for (;;) {
        if (od->limit >= 0 && addr - od->skip >= od->limit) break;
        int c = odGetc(od);
        if (c < 0) break;
        addr++;
        if (isprint(c) && c < 127) {
            if (len == 0) start = addr - 1;
            if (len + 2 > cap) s = (char *)realloc(s, cap *= 2);
            s[len++] = (char)c;
            continue;
        }
        if (c == 0 && len >= (size_t)od->stringMin) {
            s[len] = '\0';
            if (od->radix != 'n') {
                odAddress(od, start);
                putchar(' ');
            }
            for (size_t i = 0; i < len; i++) putchar(s[i]);
            putchar('\n');
        }
        len = 0;
    }
    free(s);
}

static const GnuLongOpt odLongs[] = {
    {"skip-bytes", GNU_REQ_ARG, 'j'}, {"address-radix", GNU_REQ_ARG, 'A'}, {"read-bytes", GNU_REQ_ARG, 'N'},
    {"format", GNU_REQ_ARG, 't'},     {"output-duplicates", GNU_NO_ARG, 'v'}, {"strings", GNU_OPT_ARG, 'S'},
    {"traditional", GNU_NO_ARG, 1},   {"width", GNU_OPT_ARG, 'w'},          {"endian", GNU_REQ_ARG, 2},
    {"help", GNU_NO_ARG, 3},          {"version", GNU_NO_ARG, 4},
};

int smallclueOdCommand(int argc, char **argv) {
    Od od;
    memset(&od, 0, sizeof(od));
    od.radix = 'o';
    od.limit = -1;
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "od", "A:aBbcDdeFfHhIij:LlN:OoS:st:vw::Xx", odLongs,
                  sizeof(odLongs) / sizeof(odLongs[0]));
    int c, status = 1;
    bool modern = false, traditional = false;
    char q[512];
    intmax_t n;
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'A':
            modern = true;
            if (!strchr("doxn", g.arg[0]) || g.arg[1]) {
                fprintf(stderr, "od: invalid output address radix '%c'; it must be one character from [doxn]\n", g.arg[0]);
                goto done;
            }
            od.radix = g.arg[0];
            break;
        case 'j':
            modern = true;
            if (odNumber(g.arg, &od.skip)) {
                fprintf(stderr, "od: invalid -j argument %s\n", gnuQuote(g.arg, q, sizeof(q)));
                goto done;
            }
            break;
        case 'N':
            modern = true;
            if (odNumber(g.arg, &od.limit)) {
                fprintf(stderr, "od: invalid -N argument %s\n", gnuQuote(g.arg, q, sizeof(q)));
                goto done;
            }
            break;
        case 'S':
            modern = true;
            od.stringMin = 3;
            if (g.arg) {
                if (odNumber(g.arg, &n) || n < 1 || n > 1 << 20) {
                    fprintf(stderr, "od: invalid -S argument %s\n", gnuQuote(g.arg, q, sizeof(q)));
                    goto done;
                }
                od.stringMin = (int)n;
            }
            break;
        case 't':
            modern = true;
            if (!odAddType(&od, g.arg)) goto done;
            break;
        case 'v': modern = true; od.verbose = true; break;
        case 'w':
            modern = true;
            od.haveWidth = true;
            od.perLine = 32;
            if (g.arg) {
                if (odNumber(g.arg, &n) || n < 1) {
                    fprintf(stderr, "od: invalid -w argument %s\n", gnuQuote(g.arg, q, sizeof(q)));
                    goto done;
                }
                od.perLine = n;
            }
            break;
        case 1: traditional = true; break;
        case 2:
            if (!strcmp(g.arg, "big")) od.bigEndian = true;
            else if (!strcmp(g.arg, "little")) od.bigEndian = false;
            else {
                char q2[64];
                fprintf(stderr, "od: invalid argument %s for %s\nValid arguments are:\n  - %s\n  - %s\n",
                        gnuQuoteLocale(g.arg, q, sizeof(q)), gnuQuoteLocale("--endian", q2, sizeof(q2)), "'big'",
                        "'little'");
                goto try;
            }
            break;
        case 'a': odAddType(&od, "a"); break;
        case 'b': odAddType(&od, "o1"); break;
        case 'c': odAddType(&od, "c"); break;
        case 'D': odAddType(&od, "u4"); break;
        case 'd': odAddType(&od, "u2"); break;
        case 'e': case 'F': odAddType(&od, "f8"); break;
        case 'f': odAddType(&od, "f4"); break;
        case 'H': case 'X': odAddType(&od, "x4"); break;
        case 'h': case 'x': odAddType(&od, "x2"); break;
        case 'I': case 'L': case 'l': odAddType(&od, "d8"); break;
        case 'i': odAddType(&od, "d4"); break;
        case 'O': odAddType(&od, "o4"); break;
        case 'o': odAddType(&od, "o2"); break;
        case 's': odAddType(&od, "d2"); break;
        case 'B': odAddType(&od, "o2"); break;
        case 3:
            fputs("Usage: od [OPTION]... [FILE]...\n"
                  "  or:  od [-abcdfilosx]... [FILE] [[+]OFFSET[.][b]]\n"
                  "  or:  od --traditional [OPTION]... [FILE] [[+]OFFSET[.][b] [+][LABEL][.][b]]\n\n"
                  "Write an unambiguous representation, octal bytes by default,\n"
                  "of FILE to standard output.\n",
                  stdout);
            status = 0;
            goto done;
        case 4: puts("od (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    /* the traditional [FILE] [[+]OFFSET[.][b]] */
    intmax_t off;
    if (!modern && g.nops >= 1 && g.nops <= (traditional ? 3 : 2)) {
        if (g.nops == 1 && g.ops[0][0] == '+' && odOldOffset(g.ops[0], &off)) {
            od.skip = off;
            g.nops = 0;
        } else if (g.nops == 2 && (traditional || g.ops[1][0] == '+') && odOldOffset(g.ops[1], &off)) {
            od.skip = off;
            g.nops = 1;
        }
    }
    if (od.nspecs == 0) odAddType(&od, "o2");
    if (od.nspecs == 0) goto done;
    {
        /* bytes per line: a multiple of every size, GNU's width rule */
        int l = 1;
        for (int i = 0; i < od.nspecs; i++) {
            int a = l, b = od.specs[i].size;
            while (b) {
                int t = a % b;
                a = b;
                b = t;
            }
            l = l / a * od.specs[i].size;
        }
        if (od.haveWidth) {
            if (od.perLine % l) {
                fprintf(stderr, "od: warning: invalid width %jd; using %d instead\n", od.perLine, l);
                od.perLine = l;
            }
        } else {
            od.perLine = l > 16 ? l : 16 / l * l;
        }
        intmax_t widest = 0;
        for (int i = 0; i < od.nspecs; i++) {
            intmax_t w = (od.specs[i].width + 1) * (od.perLine / od.specs[i].size);
            if (w > widest) widest = w;
        }
        for (int i = 0; i < od.nspecs; i++)
            od.specs[i].pad = widest - od.specs[i].width * (od.perLine / od.specs[i].size);
    }
    static char *dash[] = {(char *)"-"};
    od.files = g.nops ? g.ops : dash;
    od.nfiles = g.nops ? g.nops : 1;
    od.status = 0;
    /* GNU opens the first readable file before anything else: none, no dump */
    {
        int first = odGetc(&od);
        if (first < 0 && !od.opened) goto finish;
        if (first >= 0) ungetc(first, od.in);
    }
    /* skip */
    for (intmax_t k = 0; k < od.skip; k++) {
        if (odGetc(&od) < 0) {
            fputs("od: cannot skip past end of combined input\n", stderr);
            od.status = 1;
            goto finish;
        }
    }
    if (od.stringMin) {
        odStrings(&od, od.skip);
        goto finish;
    }
    {
        unsigned char *block = (unsigned char *)calloc(1, (size_t)od.perLine * 2 + 16);
        unsigned char *prev = block + od.perLine + 8;
        intmax_t addr = od.skip, total = 0;
        bool havePrev = false, starred = false;
        for (;;) {
            intmax_t len = 0;
            while (len < od.perLine && (od.limit < 0 || total < od.limit)) {
                int ch = odGetc(&od);
                if (ch < 0) break;
                block[len++] = (unsigned char)ch;
                total++;
            }
            if (len == 0) break;
            if (len == od.perLine && havePrev && !od.verbose && !memcmp(block, prev, (size_t)len)) {
                if (!starred) {
                    puts("*");
                    starred = true;
                }
            } else {
                memset(block + len, 0, (size_t)(od.perLine - len + 8));
                odLine(&od, addr, block, len);
                starred = false;
            }
            memcpy(prev, block, (size_t)od.perLine);
            havePrev = len == od.perLine;
            addr += len;
            if (len < od.perLine) break;
        }
        if (od.radix != 'n') {
            odAddress(&od, addr);
            putchar('\n');
        }
        free(block);
    }
finish:
    if (od.in && od.in != stdin) fclose(od.in);
    status = od.status;
    goto done;
try:
    status = odTry();
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("od", errno);
        status = 1;
    }
    return status;
}
