/*
 * seq: GNU coreutils 9 compatible. FIRST/INCREMENT/LAST in any form
 * strtold takes (decimal, exponent, hex, inf), -f FORMAT with GNU's
 * validation, -s, -w with GNU's width and precision rules, negative
 * numbers as operands, and GNU's "print the number just past LAST when it
 * prints as LAST" rule. Decimal operands are stepped in exact decimal
 * arithmetic -- GNU's long double is exact over the ranges scripts use, a
 * double is not (seq 9999999999999999999 10000000000000000001 never
 * advanced) -- and hex or infinite ones in floating point.
 */

#include "seq_app.h"

#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Exact decimals: sign and magnitude in base 1e9, scaled by 10^scale. --- */

#define SEQ_BASE 1000000000u

typedef struct {
    uint32_t *d;   /* little-endian limbs */
    size_t n;
    bool neg;
} SeqNum;

static void seqTrim(SeqNum *x) {
    while (x->n && !x->d[x->n - 1]) x->n--;
}

/* digits: decimal digits only; the value digits * 10^shift. */
static bool seqFromDigits(SeqNum *x, const char *digits, size_t len, size_t shift) {
    size_t total = len + shift;
    x->n = total / 9 + 1;
    x->d = (uint32_t *)calloc(x->n, sizeof(uint32_t));
    if (!x->d) return false;
    for (size_t i = 0; i < total; i++) {
        size_t pos = total - 1 - i;   /* power of ten of this digit */
        uint32_t v = i < len ? (uint32_t)(digits[i] - '0') : 0;
        uint32_t p = 1;
        for (size_t k = 0; k < pos % 9; k++) p *= 10;
        x->d[pos / 9] += v * p;
    }
    seqTrim(x);
    return true;
}

static int seqCmpMag(const SeqNum *a, const SeqNum *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (size_t i = a->n; i-- > 0;)
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    return 0;
}

static int seqCmp(const SeqNum *a, const SeqNum *b) {
    bool an = a->neg && a->n, bn = b->neg && b->n;
    if (an != bn) return an ? -1 : 1;
    int m = seqCmpMag(a, b);
    return an ? -m : m;
}

/* a += b */
static bool seqAdd(SeqNum *a, const SeqNum *b) {
    size_t n = (a->n > b->n ? a->n : b->n) + 1;
    uint32_t *d = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!d) return false;
    bool an = a->neg && a->n, bn = b->neg && b->n;
    if (an == bn) {
        uint64_t carry = 0;
        for (size_t i = 0; i < n; i++) {
            uint64_t s = carry + (i < a->n ? a->d[i] : 0) + (i < b->n ? b->d[i] : 0);
            d[i] = (uint32_t)(s % SEQ_BASE);
            carry = s / SEQ_BASE;
        }
        a->neg = an;
    } else {
        const SeqNum *big = seqCmpMag(a, b) >= 0 ? a : b, *small = big == a ? b : a;
        int64_t borrow = 0;
        for (size_t i = 0; i < n; i++) {
            int64_t s = (int64_t)(i < big->n ? big->d[i] : 0) - (i < small->n ? small->d[i] : 0) - borrow;
            borrow = s < 0;
            d[i] = (uint32_t)(s < 0 ? s + SEQ_BASE : s);
        }
        a->neg = big == a ? an : bn;
    }
    free(a->d);
    a->d = d;
    a->n = n;
    seqTrim(a);
    if (!a->n) a->neg = false;   /* -1 + 1 is +0, as in IEEE */
    return true;
}

/* The magnitude's decimal digits, at least one. */
static char *seqDigits(const SeqNum *x) {
    char *s = (char *)malloc(x->n * 9 + 2);
    if (!s) return NULL;
    if (!x->n) {
        strcpy(s, "0");
        return s;
    }
    char *p = s + sprintf(s, "%u", x->d[x->n - 1]);
    for (size_t i = x->n - 1; i-- > 0;) p += sprintf(p, "%09u", x->d[i]);
    return s;
}

/* printf("%0W.Pf") (zero true) or ("%.Pf") of x / 10^scale, rounding the
 * dropped digits half to even. */
static char *seqFormatFixed(const SeqNum *x, size_t scale, int prec, int width, bool zero) {
    char *digits = seqDigits(x);
    if (!digits) return NULL;
    size_t len = strlen(digits);
    if (len <= scale) {   /* left-pad so there is an integer digit */
        char *p = (char *)malloc(scale + 2);
        memset(p, '0', scale + 1 - len);
        memcpy(p + scale + 1 - len, digits, len + 1);
        free(digits);
        digits = p;
        len = scale + 1;
    }
    size_t intLen = len - scale;
    size_t keep = intLen + ((size_t)prec < scale ? (size_t)prec : scale);
    if (keep < len) {   /* round */
        char first = digits[keep];
        bool rest = false;
        for (size_t i = keep + 1; i < len; i++) rest |= digits[i] != '0';
        bool up = first > '5' || (first == '5' && (rest || (keep && (digits[keep - 1] - '0') % 2)));
        digits[keep] = '\0';
        if (up) {
            size_t i = keep;
            while (i > 0 && digits[i - 1] == '9') digits[--i] = '0';
            if (i == 0) {
                memmove(digits + 1, digits, keep + 1);
                digits[0] = '1';
                intLen++;
                keep++;
            } else {
                digits[i - 1]++;
            }
        }
    }
    size_t fracHave = keep - intLen;
    size_t need = 2 + intLen + 1 + (size_t)prec + (width > 0 ? (size_t)width : 0) + 2;
    char *out = (char *)malloc(need);
    char *body = (char *)malloc(need);
    size_t o = 0;
    memcpy(body, digits, intLen);
    o = intLen;
    if (prec > 0) {
        body[o++] = '.';
        memcpy(body + o, digits + intLen, fracHave);
        o += fracHave;
        for (size_t k = fracHave; k < (size_t)prec; k++) body[o++] = '0';
    }
    body[o] = '\0';
    bool neg = x->neg;
    size_t blen = o + (neg ? 1 : 0);
    size_t pad = width > 0 && (size_t)width > blen ? (size_t)width - blen : 0;
    o = 0;
    if (!zero)
        for (; pad; pad--) out[o++] = ' ';
    if (neg) out[o++] = '-';
    for (; pad; pad--) out[o++] = '0';
    strcpy(out + o, body);
    free(body);
    free(digits);
    return out;
}

/* x / 10^scale as text strtod can read back. */
static double seqToDouble(const SeqNum *x, size_t scale) {
    char *s = seqFormatFixed(x, scale, (int)scale, 0, false);
    double v = s ? strtod(s, NULL) : 0;
    free(s);
    return v;
}

/* --- Operands. --- */

typedef struct {
    long double value;
    int width, precision;   /* GNU's scan_arg; precision INT_MAX: unknown */
    bool decimal;           /* plain decimal: exact arithmetic applies */
    bool neg;
    char *digits;           /* decimal: all significant digits */
    long exp10;             /* decimal: value = digits * 10^exp10 */
} SeqArg;

static int seqTry(void) {
    fputs("Try 'seq --help' for more information.\n", stderr);
    return 1;
}

/* false after GNU's message. */
static bool seqScan(const char *arg, SeqArg *r) {
    char q[512], q2[64];
    memset(r, 0, sizeof(*r));
    char *end;
    errno = 0;
    double dv = strtod(arg, &end);
    if (end == arg || *end || (errno == ERANGE && isinf(dv))) {
        /* GNU's long double reaches 1e4932; a decimal past a double's range
         * is still a number below */
        const char *p = arg;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '+' || *p == '-') p++;
        bool digit = false;
        while (isdigit((unsigned char)*p)) p++, digit = true;
        if (*p == '.') for (p++; isdigit((unsigned char)*p); p++) digit = true;
        if (digit && (*p == 'e' || *p == 'E')) {
            p++;
            if (*p == '+' || *p == '-') p++;
            bool ed = false;
            while (isdigit((unsigned char)*p)) p++, ed = true;
            if (!ed) digit = false;
        }
        if (!digit || *p) {
            fprintf(stderr, "seq: invalid floating point argument: %s\n", gnuQuoteLocale(arg, q, sizeof(q)));
            return false;
        }
    }
    if (isnan(dv)) {
        fprintf(stderr, "seq: invalid %s argument: %s\n", gnuQuoteLocale("not-a-number", q2, sizeof(q2)),
                gnuQuoteLocale(arg, q, sizeof(q)));
        return false;
    }
    r->value = dv;
    while (isspace((unsigned char)*arg) || *arg == '+') arg++;
    r->precision = INT_MAX;
    const char *dot = strchr(arg, '.');
    if (!dot && !strchr(arg, 'p')) r->precision = 0;
    bool hexish = arg[strcspn(arg, "xX")] != '\0';
    const char *e = strchr(arg, 'e');
    if (!e) e = strchr(arg, 'E');
    if (!hexish && !isinf(dv) && !strpbrk(arg, "iInN")) {
        size_t fraction = 0;
        long w = (long)strlen(arg);
        if (dot) {
            fraction = strcspn(dot + 1, "eE");
            if (fraction <= INT_MAX) r->precision = (int)fraction;
            w += fraction == 0 ? -1 : (dot == arg || !isdigit((unsigned char)dot[-1]));
        }
        if (e) {
            long exponent = strtol(e + 1, NULL, 10);
            if (exponent < -LONG_MAX) exponent = -LONG_MAX;
            r->precision += exponent < 0 ? (int)-exponent : -(int)(r->precision < exponent ? r->precision : exponent);
            w -= (long)(strlen(arg) - (size_t)(e - arg));
            if (exponent < 0) {
                if (dot) {
                    if (e == dot + 1) w++;
                } else {
                    w++;
                }
                exponent = -exponent;
            } else {
                if (dot && r->precision == 0 && fraction) w--;
                exponent -= (long)fraction < exponent ? (long)fraction : exponent;
            }
            w += exponent;
        }
        r->width = (int)w;
        /* the exact value */
        const char *p = arg;
        r->neg = *p == '-';
        if (*p == '-') p++;
        size_t cap = strlen(p) + 1;
        r->digits = (char *)malloc(cap);
        size_t n = 0;
        long frac = 0;
        bool afterDot = false;
        for (; *p && *p != 'e' && *p != 'E'; p++) {
            if (*p == '.') { afterDot = true; continue; }
            r->digits[n++] = *p;
            if (afterDot) frac++;
        }
        r->digits[n] = '\0';
        r->exp10 = (e ? strtol(e + 1, NULL, 10) : 0) - frac;
        r->decimal = true;
    }
    return true;
}

/* GNU's long_double_format check; the format for a double, or NULL. */
static char *seqCheckFormat(const char *fmt) {
    char q[512];
    size_t i = 0;
    for (; !(fmt[i] == '%' && fmt[i + 1] != '%'); i += (fmt[i] == '%') + 1)
        if (!fmt[i]) {
            fprintf(stderr, "seq: format %s has no %% directive\n", gnuQuoteLocale(fmt, q, sizeof(q)));
            return NULL;
        }
    i++;
    i += strspn(fmt + i, "-+#0 '");
    i += strspn(fmt + i, "0123456789");
    if (fmt[i] == '.') {
        i++;
        i += strspn(fmt + i, "0123456789");
    }
    size_t lm = i;
    bool hasL = fmt[i] == 'L';
    i += hasL;
    if (!fmt[i]) {
        fprintf(stderr, "seq: format %s ends in %%\n", gnuQuoteLocale(fmt, q, sizeof(q)));
        return NULL;
    }
    if (!strchr("efgaEFGA", fmt[i])) {
        fprintf(stderr, "seq: format %s has unknown %%%c directive\n", gnuQuoteLocale(fmt, q, sizeof(q)), fmt[i]);
        return NULL;
    }
    for (i++;; i += (fmt[i] == '%') + 1) {
        if (fmt[i] == '%' && fmt[i + 1] != '%') {
            fprintf(stderr, "seq: format %s has too many %% directives\n", gnuQuoteLocale(fmt, q, sizeof(q)));
            return NULL;
        }
        if (!fmt[i]) break;
    }
    char *out = (char *)malloc(strlen(fmt) + 1);
    memcpy(out, fmt, lm);
    strcpy(out + lm, fmt + lm + hasL);   /* a double, not a long double */
    return out;
}

static const GnuLongOpt seqLongs[] = {
    {"equal-width", GNU_NO_ARG, 'w'}, {"format", GNU_REQ_ARG, 'f'}, {"separator", GNU_REQ_ARG, 's'},
    {"help", GNU_NO_ARG, 3},          {"version", GNU_NO_ARG, 4},
};

typedef struct {
    const char *sep;
    char *fmt;          /* user format for a double, or NULL */
    bool exact;
    size_t scale;
    int prec, width;    /* default fixed format; prec < 0: %g */
    bool zero;
} SeqOut;

/* One number as text. */
static char *seqText(const SeqOut *o, const SeqNum *x, double v) {
    if (o->exact && !o->fmt && o->prec >= 0) return seqFormatFixed(x, o->scale, o->prec, o->width, o->zero);
    double dv = o->exact ? seqToDouble(x, o->scale) : v;
    if (o->exact && x->neg && !x->n) dv = -0.0;
    char *s = NULL;
    if (o->fmt) {
        if (asprintf(&s, o->fmt, dv) < 0) s = NULL;
    } else if (o->prec >= 0 && o->zero) {
        if (asprintf(&s, "%0*.*f", o->width, o->prec, dv) < 0) s = NULL;
    } else if (o->prec >= 0) {
        if (asprintf(&s, "%.*f", o->prec, dv) < 0) s = NULL;
    } else if (asprintf(&s, "%g", dv) < 0) {
        s = NULL;
    }
    return s;
}

int smallclueSeqCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "seq", "+f:s:w", seqLongs, sizeof(seqLongs) / sizeof(seqLongs[0]));
    g.inOrder = true;
    const char *format = NULL;
    SeqOut o = {"\n", NULL, false, 0, -1, 0, false};
    bool equal = false;
    int status = 1, c, first = argc;
    char q[512];
    SeqArg a[3];
    memset(a, 0, sizeof(a));
    SeqNum x = {0}, step = {0}, last = {0};
    for (;;) {
        if (!g.cluster && g.ind < argc && argv[g.ind][0] == '-' &&
            (argv[g.ind][1] == '.' || isdigit((unsigned char)argv[g.ind][1]))) {
            first = g.ind;   /* a negative number: the operands start here */
            break;
        }
        c = gnuGetopt(&g);
        if (c == -1) {
            first = g.ind;
            break;
        }
        if (c == 1) {
            first = g.ind - 1;
            break;
        }
        switch (c) {
        case 'f': format = g.arg; break;
        case 's': o.sep = g.arg; break;
        case 'w': equal = true; break;
        case 3:
            fputs("Usage: seq [OPTION]... LAST\n"
                  "  or:  seq [OPTION]... FIRST LAST\n"
                  "  or:  seq [OPTION]... FIRST INCREMENT LAST\n"
                  "Print numbers from FIRST to LAST, in steps of INCREMENT.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -f, --format=FORMAT      use printf style floating-point FORMAT\n"
                  "  -s, --separator=STRING   use STRING to separate numbers (default: \\n)\n"
                  "  -w, --equal-width        equalize width by padding with leading zeroes\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            status = 0;
            goto done;
        case 4:
            puts("seq (SmallCLUE) 9.4");
            status = 0;
            goto done;
        default:
            goto try;
        }
    }
    if (g.done && first > g.ind) first = g.ind;
    int nargs = argc - first;
    if (nargs < 1) {
        fputs("seq: missing operand\n", stderr);
        goto try;
    }
    if (nargs > 3) {
        fprintf(stderr, "seq: extra operand %s\n", gnuQuoteLocale(argv[first + 3], q, sizeof(q)));
        goto try;
    }
    if (format && !(o.fmt = seqCheckFormat(format))) goto done;
    {
        SeqArg *fa = &a[0], *sa = &a[1], *la = &a[2];
        const char *one = "1";
        fa->value = 1, fa->precision = 0, fa->width = 1, fa->decimal = true, fa->digits = strdup(one);
        sa->value = 1, sa->precision = 0, sa->width = 1, sa->decimal = true, sa->digits = strdup(one);
        if (nargs == 1) {
            if (!seqScan(argv[first], la)) goto try;
        } else {
            free(fa->digits);
            if (!seqScan(argv[first], fa)) goto try;
            if (nargs == 3) {
                free(sa->digits);
                if (!seqScan(argv[first + 1], sa)) goto try;
                if (sa->value == 0) {
                    fprintf(stderr, "seq: invalid Zero increment value: %s\n",
                            gnuQuoteLocale(argv[first + 1], q, sizeof(q)));
                    goto try;
                }
            }
            if (!seqScan(argv[first + nargs - 1], la)) goto try;
        }
        if (format && equal) {
            fputs("seq: format string may not be specified when printing equal width strings\n", stderr);
            goto try;
        }
        /* get_default_format */
        int prec = fa->precision > sa->precision ? fa->precision : sa->precision;
        if (!format) {
            if (prec != INT_MAX && la->precision != INT_MAX) {
                o.prec = prec;
                if (equal) {
                    long fw = fa->width + (prec - fa->precision);
                    long lw = la->width + (prec - la->precision);
                    if (la->precision && prec == 0) lw--;
                    if (la->precision == 0 && prec) lw++;
                    if (fa->precision == 0 && prec) fw++;
                    o.width = (int)(fw > lw ? fw : lw);
                    o.zero = true;
                }
            }
        }
        bool infLast = !la->decimal && isinf(la->value);
        o.exact = fa->decimal && sa->decimal && (la->decimal || infLast);
        if (o.exact) {
            long minExp = 0;
            for (int i = 0; i < 3; i++)
                if (a[i].decimal && a[i].exp10 < minExp) minExp = a[i].exp10;
            o.scale = (size_t)-minExp;
            SeqNum *t[3] = {&x, &step, &last};
            for (int i = 0; i < 3; i++) {
                if (!a[i].decimal) continue;
                seqFromDigits(t[i], a[i].digits, strlen(a[i].digits), (size_t)(a[i].exp10 - minExp));
                t[i]->neg = a[i].neg;
            }
            bool negStep = step.neg && step.n;
            /* out_of_range against LAST, or never with LAST at the right infinity */
#define SEQ_PAST() (infLast ? (la->value > 0) == negStep : negStep ? seqCmp(&x, &last) < 0 : seqCmp(&last, &x) < 0)
            if (!SEQ_PAST()) {
                char *prev = seqText(&o, &x, 0);
                fputs(prev, stdout);
                for (;;) {
                    seqAdd(&x, &step);
                    if (SEQ_PAST()) {
                        /* the number just past LAST, when it prints as LAST and
                         * not as the number before it */
                        char *s = seqText(&o, &x, 0);
                        /* exact: past LAST is never LAST, unless a -f format rounds it there */
                        bool extra = o.fmt && !infLast && strtod(s, NULL) == (double)la->value && strcmp(s, prev);
                        if (!extra) {
                            free(s);
                            break;
                        }
                        fputs(o.sep, stdout);
                        fputs(s, stdout);
                        free(prev);
                        prev = s;
                        break;
                    }
                    char *s = seqText(&o, &x, 0);
                    fputs(o.sep, stdout);
                    fputs(s, stdout);
                    free(prev);
                    prev = s;
                    if (ferror(stdout)) break;
                }
                free(prev);
                fputs("\n", stdout);
            }
#undef SEQ_PAST
        } else {
            double f = (double)fa->value, st = (double)sa->value, l = (double)la->value;
            if (!(st < 0 ? f < l : l < f)) {
                char *prev = seqText(&o, NULL, f);
                fputs(prev, stdout);
                for (double i = 1;; i++) {
                    double v = f + i * st;
                    if (st < 0 ? v < l : l < v) {
                        char *s = seqText(&o, NULL, v);
                        bool extra = strtod(s, NULL) == l && strcmp(s, prev);
                        if (extra) {
                            fputs(o.sep, stdout);
                            fputs(s, stdout);
                        }
                        free(s);
                        break;
                    }
                    char *s = seqText(&o, NULL, v);
                    fputs(o.sep, stdout);
                    fputs(s, stdout);
                    free(prev);
                    prev = s;
                    if (ferror(stdout)) break;
                }
                free(prev);
                fputs("\n", stdout);
            }
        }
    }
    status = 0;
    goto done;
try:
    status = seqTry();
done:
    for (int i = 0; i < 3; i++) free(a[i].digits);
    free(x.d);
    free(step.d);
    free(last.d);
    free(o.fmt);
    gnuGetoptFree(&g);
    if ((fflush(stdout) != 0 || ferror(stdout)) && status == 0) {
        gnuWriteError("seq", errno);
        status = 1;
    }
    return status;
}
