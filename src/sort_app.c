/*
 * sort: sort lines of text, compatible with GNU coreutils 9 in the C and
 * C.UTF-8 locales (byte order).
 *
 * The sort this replaces took one key, and only "-k N" (field N to the end of
 * the line): `sort -k2,2n`, two -k options, `-k1.3` and per-key options all
 * sorted wrongly without a word. It had no -o, -h, -V, -M, -g, -R, -z, -d,
 * -i, and its -m re-sorted. This ports GNU's field rules (begfield/limfield),
 * key option inheritance, numeric, human, general, month, version
 * (filevercmp) and random orderings, the last-resort whole-line comparison,
 * a real merge for -m, -c/-C, and GNU's messages and exit statuses (2 for
 * trouble, 1 for disorder).
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sort_app.h"
#include "app_hooks.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SORT_FAILURE 2
#define SORT_NOEND SIZE_MAX

typedef struct SortKey {
    size_t sword, schar;   /* start field and character, 0-based */
    size_t eword, echar;   /* end; eword SORT_NOEND: end of line; echar 0: whole field */
    bool skipsblanks, skipeblanks;
    int ignore;            /* 0, 'd' (non-dictionary), 'i' (non-printing) */
    bool translate;        /* -f */
    bool numeric, general, human, month, random, version, reverse;
} SortKey;

typedef struct {
    const char *text;
    size_t len;
} SortLine;

typedef struct {
    SortKey *keys;
    size_t nkeys;
    bool reverse, unique, stable;
    int tab;               /* -1: blank-separated fields */
    uint64_t seed;
    char *buf[2];          /* scratch for transformed keys */
    size_t cap[2];
} SortCtx;

typedef struct {
    SortLine *v;
    size_t n, cap;
} SortLines;

static bool sortBlank(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n';
}

/* --- Field positions: GNU's begfield and limfield. --- */

static const char *sortBegField(const SortCtx *x, const SortLine *l, const SortKey *k) {
    const char *p = l->text, *lim = p + l->len;
    size_t sword = k->sword == SORT_NOEND ? 0 : k->sword;
    if (x->tab >= 0) {
        while (p < lim && sword--) {
            while (p < lim && *p != (char)x->tab) p++;
            if (p < lim) p++;
        }
    } else {
        while (p < lim && sword--) {
            while (p < lim && sortBlank((unsigned char)*p)) p++;
            while (p < lim && !sortBlank((unsigned char)*p)) p++;
        }
    }
    if (k->skipsblanks)
        while (p < lim && sortBlank((unsigned char)*p)) p++;
    return (size_t)(lim - p) < k->schar ? lim : p + k->schar;
}

static const char *sortLimField(const SortCtx *x, const SortLine *l, const SortKey *k) {
    const char *p = l->text, *lim = p + l->len;
    if (k->eword == SORT_NOEND) return lim;
    size_t eword = k->eword, echar = k->echar;
    if (echar == 0) eword++;
    if (x->tab >= 0) {
        while (p < lim && eword--) {
            while (p < lim && *p != (char)x->tab) p++;
            if (p < lim && (eword || echar)) p++;
        }
    } else {
        while (p < lim && eword--) {
            while (p < lim && sortBlank((unsigned char)*p)) p++;
            while (p < lim && !sortBlank((unsigned char)*p)) p++;
        }
    }
    if (echar != 0) {
        if (k->skipeblanks)
            while (p < lim && sortBlank((unsigned char)*p)) p++;
        p = (size_t)(lim - p) < echar ? lim : p + echar;
    }
    return p;
}

/* --- Orderings. --- */

/* GNU's strnumcmp in the C locale: optional '-', digits, optional '.'
 * fraction; anything else ends the number, and no number is zero. */
typedef struct {
    bool neg;
    const char *ip; size_t il;   /* integer digits, leading zeros dropped */
    const char *fp; size_t fl;   /* fraction digits, trailing zeros dropped */
    const char *end;             /* just past the number */
} SortNum;

static SortNum sortParseNum(const char *s, const char *lim) {
    SortNum n = {false, s, 0, s, 0, s};
    while (s < lim && sortBlank((unsigned char)*s)) s++;
    if (s < lim && *s == '-') { n.neg = true; s++; }
    while (s < lim && *s == '0') s++;
    n.ip = s;
    while (s < lim && isdigit((unsigned char)*s)) s++;
    n.il = (size_t)(s - n.ip);
    n.fp = s;
    if (s < lim && *s == '.') {
        s++;
        n.fp = s;
        while (s < lim && isdigit((unsigned char)*s)) s++;
        n.fl = (size_t)(s - n.fp);
        while (n.fl > 0 && n.fp[n.fl - 1] == '0') n.fl--;
    }
    n.end = s;
    if (n.il == 0 && n.fl == 0) n.neg = false;   /* -0 is 0 */
    return n;
}

static int sortNumCmp(const char *a, const char *alim, const char *b, const char *blim) {
    SortNum x = sortParseNum(a, alim), y = sortParseNum(b, blim);
    if (x.neg != y.neg) return x.neg ? -1 : 1;
    int r;
    if (x.il != y.il) {
        r = x.il < y.il ? -1 : 1;
    } else if ((r = memcmp(x.ip, y.ip, x.il)) != 0) {
        r = r < 0 ? -1 : 1;
    } else {
        size_t m = x.fl < y.fl ? x.fl : y.fl;
        r = memcmp(x.fp, y.fp, m);
        if (r) r = r < 0 ? -1 : 1;
        else r = (x.fl > y.fl) - (x.fl < y.fl);
    }
    return x.neg ? -r : r;
}

/* -h: the SI suffix decides first, then the number. As GNU's
 * find_unit_order, a number with no nonzero digit has no unit. */
static int sortUnitOrder(const char *s, const char *lim) {
    while (s < lim && sortBlank((unsigned char)*s)) s++;
    bool neg = s < lim && *s == '-';
    if (neg) s++;
    char maxDigit = '\0';
    for (;;) {
        while (s < lim && isdigit((unsigned char)*s)) {
            if (*s > maxDigit) maxDigit = *s;
            s++;
        }
        if (s < lim && *s == '.') { s++; continue; }
        break;
    }
    if (maxDigit <= '0' || s >= lim) return 0;
    static const char units[] = "KMGTPEZYRQ";
    char c = *s == 'k' ? 'K' : *s;
    const char *u = c ? strchr(units, c) : NULL;
    int order = u ? (int)(u - units) + 1 : 0;
    return neg ? -order : order;
}

static int sortMonth(const char *s, const char *lim) {
    static const char *const names[] = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN",
                                        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};
    while (s < lim && sortBlank((unsigned char)*s)) s++;
    if (lim - s < 3) return 0;
    for (int m = 0; m < 12; m++)
        if (toupper((unsigned char)s[0]) == names[m][0] && toupper((unsigned char)s[1]) == names[m][1] &&
            toupper((unsigned char)s[2]) == names[m][2])
            return m + 1;
    return 0;
}

/* gnulib's filevercmp, as `sort -V` and `ls -v` use it. */
static int sortVerOrder(const char *s, size_t pos, size_t len) {
    if (pos == len) return -1;
    unsigned char c = (unsigned char)s[pos];
    if (isdigit(c)) return 0;
    if (isalpha(c)) return c;
    if (c == '~') return -2;
    return c + UCHAR_MAX + 1;
}

static int sortVerRevCmp(const char *a, size_t al, const char *b, size_t bl) {
    size_t i = 0, j = 0;
    while (i < al || j < bl) {
        int firstDiff = 0;
        while ((i < al && !isdigit((unsigned char)a[i])) || (j < bl && !isdigit((unsigned char)b[j]))) {
            int ac = sortVerOrder(a, i, al), bc = sortVerOrder(b, j, bl);
            if (ac != bc) return ac - bc;
            i++;
            j++;
        }
        while (i < al && a[i] == '0') i++;
        while (j < bl && b[j] == '0') j++;
        while (i < al && j < bl && isdigit((unsigned char)a[i]) && isdigit((unsigned char)b[j])) {
            if (!firstDiff) firstDiff = (unsigned char)a[i] - (unsigned char)b[j];
            i++;
            j++;
        }
        if (i < al && isdigit((unsigned char)a[i])) return 1;
        if (j < bl && isdigit((unsigned char)b[j])) return -1;
        if (firstDiff) return firstDiff;
    }
    return 0;
}

/* Length without the trailing run of (\.[A-Za-z~][A-Za-z0-9~]*)* suffixes. */
static size_t sortVerPrefix(const char *s, size_t n) {
    size_t prefix = 0;
    for (size_t i = 0;;) {
        if (i == n) return prefix;
        i++;
        prefix = i;
        while (i + 1 < n && s[i] == '.' && (isalpha((unsigned char)s[i + 1]) || s[i + 1] == '~'))
            for (i += 2; i < n && (isalnum((unsigned char)s[i]) || s[i] == '~'); i++) {}
    }
}

static int sortVersion(const char *a, size_t al, const char *b, size_t bl) {
    if (al == 0) return -(bl != 0);
    if (bl == 0) return 1;
    if (a[0] == '.') {
        if (b[0] != '.') return -1;
        bool adot = al == 1, bdot = bl == 1;
        if (adot) return -!bdot;
        if (bdot) return 1;
        bool add = a[1] == '.' && al == 2, bdd = b[1] == '.' && bl == 2;
        if (add) return -!bdd;
        if (bdd) return 1;
    } else if (b[0] == '.') {
        return 1;
    }
    size_t ap = sortVerPrefix(a, al), bp = sortVerPrefix(b, bl);
    int r = sortVerRevCmp(a, ap, b, bp);
    return r || (ap == al && bp == bl) ? r : sortVerRevCmp(a, al, b, bl);
}

static uint64_t sortHash(uint64_t seed, const char *s, size_t n) {
    uint64_t h = seed ^ 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001b3ULL;
    }
    h ^= h >> 33; h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

static int sortGeneral(SortCtx *x, const char *a, size_t al, const char *b, size_t bl) {
    for (int i = 0; i < 2; i++) {
        size_t need = (i ? bl : al) + 1;
        if (x->cap[i] < need) {
            char *n = (char *)realloc(x->buf[i], need);
            if (!n) return 0;
            x->buf[i] = n;
            x->cap[i] = need;
        }
        memcpy(x->buf[i], i ? b : a, need - 1);
        x->buf[i][need - 1] = '\0';
    }
    char *ea, *eb;
    long double va = strtold(x->buf[0], &ea), vb = strtold(x->buf[1], &eb);
    /* Conversion failures first, then NaNs, then numbers; -0 == +0. */
    if (ea == x->buf[0]) return eb == x->buf[1] ? 0 : -1;
    if (eb == x->buf[1]) return 1;
    if (va < vb) return -1;
    if (va > vb) return 1;
    if (va == vb) return 0;
    if (vb == vb) return -1;
    if (va == va) return 1;
    return 0;
}

/* Copies [s, lim) into scratch slot i, dropping ignored bytes and folding. */
static bool sortTransform(SortCtx *x, int i, const SortKey *k, const char **s, const char **lim) {
    size_t n = (size_t)(*lim - *s);
    if (x->cap[i] < n + 1) {
        char *nb = (char *)realloc(x->buf[i], n + 1);
        if (!nb) return false;
        x->buf[i] = nb;
        x->cap[i] = n + 1;
    }
    size_t o = 0;
    for (const char *p = *s; p < *lim; p++) {
        unsigned char c = (unsigned char)*p;
        if (k->ignore == 'd' && !isalnum(c) && !sortBlank(c)) continue;
        if (k->ignore == 'i' && !isprint(c)) continue;
        x->buf[i][o++] = (char)(k->translate ? toupper(c) : c);
    }
    *s = x->buf[i];
    *lim = x->buf[i] + o;
    return true;
}

static int sortKeyCompare(SortCtx *x, const SortLine *a, const SortLine *b) {
    for (size_t i = 0; i < x->nkeys; i++) {
        const SortKey *k = &x->keys[i];
        const char *ta = sortBegField(x, a, k), *la = sortLimField(x, a, k);
        const char *tb = sortBegField(x, b, k), *lb = sortLimField(x, b, k);
        if (la < ta) la = ta;
        if (lb < tb) lb = tb;
        if (k->ignore || k->translate) {
            /* Slot 1 is filled second, so a's copy survives b's. */
            if (!sortTransform(x, 0, k, &ta, &la) || !sortTransform(x, 1, k, &tb, &lb)) return 0;
        }
        size_t lena = (size_t)(la - ta), lenb = (size_t)(lb - tb);
        int diff;
        if (k->numeric) {
            diff = sortNumCmp(ta, la, tb, lb);
        } else if (k->human) {
            diff = sortUnitOrder(ta, la) - sortUnitOrder(tb, lb);
            if (!diff) diff = sortNumCmp(ta, la, tb, lb);
        } else if (k->general) {
            /* sortGeneral reuses the scratch slots: copy out first. */
            char *ca = (char *)malloc(lena + 1), *cb = (char *)malloc(lenb + 1);
            if (!ca || !cb) { free(ca); free(cb); return 0; }
            memcpy(ca, ta, lena);
            memcpy(cb, tb, lenb);
            diff = sortGeneral(x, ca, lena, cb, lenb);
            free(ca);
            free(cb);
        } else if (k->month) {
            diff = sortMonth(ta, la) - sortMonth(tb, lb);
        } else if (k->random) {
            uint64_t ha = sortHash(x->seed, ta, lena), hb = sortHash(x->seed, tb, lenb);
            diff = ha < hb ? -1 : ha > hb;
            if (!diff) {
                diff = memcmp(ta, tb, lena < lenb ? lena : lenb);
                if (!diff) diff = (lena > lenb) - (lena < lenb);
            }
        } else if (k->version) {
            diff = sortVersion(ta, lena, tb, lenb);
        } else {
            diff = memcmp(ta, tb, lena < lenb ? lena : lenb);
            if (!diff) diff = (lena > lenb) - (lena < lenb);
        }
        if (diff) return k->reverse ? (diff < 0 ? 1 : -1) : (diff < 0 ? -1 : 1);
    }
    return 0;
}

static int sortCompare(SortCtx *x, const SortLine *a, const SortLine *b) {
    if (x->nkeys) {
        int d = sortKeyCompare(x, a, b);
        if (d || x->unique || x->stable) return d;
    }
    int d = memcmp(a->text, b->text, a->len < b->len ? a->len : b->len);
    if (!d) d = (a->len > b->len) - (a->len < b->len);
    else d = d < 0 ? -1 : 1;
    return x->reverse ? -d : d;
}

/* A stable merge sort: equal lines keep their input order. */
static void sortMerge(SortCtx *x, SortLine *v, SortLine *tmp, size_t n) {
    if (n < 2) return;
    size_t mid = n / 2;
    sortMerge(x, v, tmp, mid);
    sortMerge(x, v + mid, tmp, n - mid);
    if (sortCompare(x, &v[mid - 1], &v[mid]) <= 0) return;
    size_t i = 0, j = mid, o = 0;
    while (i < mid && j < n) tmp[o++] = sortCompare(x, &v[i], &v[j]) <= 0 ? v[i++] : v[j++];
    while (i < mid) tmp[o++] = v[i++];
    memcpy(v, tmp, o * sizeof(SortLine));
}

/* --- Input. --- */

typedef struct {
    char **bufs;
    size_t n;
} SortBuffers;

static bool sortPush(SortLines *l, const char *t, size_t n) {
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 1024;
        SortLine *v = (SortLine *)realloc(l->v, cap * sizeof(SortLine));
        if (!v) return false;
        l->v = v;
        l->cap = cap;
    }
    l->v[l->n].text = t;
    l->v[l->n].len = n;
    l->n++;
    return true;
}

static void sortDie(const char *what, const char *name, int err) {
    char q[4096];
    fprintf(stderr, "sort: %s: %s: %s\n", what, gnuQuoteMaybe(name, q, sizeof(q)), strerror(err));
}

/* Reads one input whole and splits it into lines; false after a message. */
static bool sortRead(const char *name, char delim, SortBuffers *keep, SortLines *out) {
    FILE *fp = NULL;
    int fd = 0;
    bool isStdin = !strcmp(name, "-");
    if (!isStdin) {
        fp = smallclueAppOpenRead(name);
        if (!fp) {
            sortDie("cannot read", name, errno);
            return false;
        }
        fd = fileno(fp);
    }
    size_t cap = 65536, len = 0;
    char *data = (char *)malloc(cap);
    bool ok = data != NULL;
    while (ok) {
        if (len == cap) {
            char *n = (char *)realloc(data, cap * 2);
            if (!n) { ok = false; errno = ENOMEM; break; }
            data = n;
            cap *= 2;
        }
        ssize_t got = read(fd, data + len, cap - len);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { ok = false; break; }
        if (got == 0) break;
        len += (size_t)got;
    }
    if (fp) fclose(fp);
    if (!ok) {
        sortDie("read failed", isStdin ? "standard input" : name, errno);
        free(data);
        return false;
    }
    char **b = (char **)realloc(keep->bufs, (keep->n + 1) * sizeof(char *));
    if (!b) { free(data); return false; }
    keep->bufs = b;
    keep->bufs[keep->n++] = data;
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == delim) {
            if (!sortPush(out, data + start, i - start)) return false;
            start = i + 1;
        }
    }
    if (start < len && !sortPush(out, data + start, len - start)) return false;
    return true;
}

/* --- Options. --- */

static bool sortKeyIsDefault(const SortKey *k) {
    return !(k->ignore || k->translate || k->skipsblanks || k->skipeblanks || k->numeric || k->general ||
             k->human || k->month || k->version || k->random);
}

/* Ordering letters after a position or as global options. */
static const char *sortSetOrdering(const char *s, SortKey *k, int blanks) {
    for (; *s; s++) {
        switch (*s) {
        case 'b':
            if (blanks != 2) k->skipsblanks = true;
            if (blanks != 1) k->skipeblanks = true;
            break;
        case 'd': k->ignore = 'd'; break;
        case 'f': k->translate = true; break;
        case 'g': k->general = true; break;
        case 'h': k->human = true; break;
        case 'i': if (!k->ignore) k->ignore = 'i'; break;
        case 'M': k->month = true; break;
        case 'n': k->numeric = true; break;
        case 'R': k->random = true; break;
        case 'r': k->reverse = true; break;
        case 'V': k->version = true; break;
        default: return s;
        }
    }
    return s;
}

static void sortKeyOpts(const SortKey *k, char *out) {
    if (k->skipsblanks || k->skipeblanks) *out++ = 'b';
    if (k->ignore == 'd') *out++ = 'd';
    if (k->translate) *out++ = 'f';
    if (k->general) *out++ = 'g';
    if (k->human) *out++ = 'h';
    if (k->ignore == 'i') *out++ = 'i';
    if (k->month) *out++ = 'M';
    if (k->numeric) *out++ = 'n';
    if (k->random) *out++ = 'R';
    if (k->reverse) *out++ = 'r';
    if (k->version) *out++ = 'V';
    *out = '\0';
}

static int sortBadSpec(const char *msg, const char *spec) {
    char q[512];
    fprintf(stderr, "sort: %s: invalid field specification %s\n", msg, gnuQuoteLocale(spec, q, sizeof(q)));
    return SORT_FAILURE;
}

static const char *sortCount(const char *s, size_t *out, bool *ok) {
    if (!isdigit((unsigned char)*s)) { *ok = false; return s; }
    size_t v = 0;
    while (isdigit((unsigned char)*s)) {
        size_t d = (size_t)(*s++ - '0');
        v = v > (SIZE_MAX - d) / 10 ? SIZE_MAX : v * 10 + d;
    }
    *out = v;
    *ok = true;
    return s;
}

/* -k POS1[,POS2]; 0 or SORT_FAILURE after a message. */
static int sortParseKey(const char *spec, SortKey *k) {
    char q[512];
    bool ok;
    memset(k, 0, sizeof(*k));
    const char *s = sortCount(spec, &k->sword, &ok);
    if (!ok) {
        fprintf(stderr, "sort: invalid number at field start: invalid count at start of %s\n", gnuQuoteLocale(spec, q, sizeof(q)));
        return SORT_FAILURE;
    }
    if (k->sword-- == 0) return sortBadSpec("field number is zero", spec);
    if (*s == '.') {
        s = sortCount(s + 1, &k->schar, &ok);
        if (!ok) {
            fprintf(stderr, "sort: invalid number after '.': invalid count at start of %s\n", gnuQuoteLocale(s, q, sizeof(q)));
            return SORT_FAILURE;
        }
        if (k->schar-- == 0) return sortBadSpec("character offset is zero", spec);
    }
    s = sortSetOrdering(s, k, 1);
    if (*s != ',') {
        k->eword = SORT_NOEND;
        k->echar = 0;
    } else {
        s = sortCount(s + 1, &k->eword, &ok);
        if (!ok) {
            fprintf(stderr, "sort: invalid number after ',': invalid count at start of %s\n", gnuQuoteLocale(s, q, sizeof(q)));
            return SORT_FAILURE;
        }
        if (k->eword-- == 0) return sortBadSpec("field number is zero", spec);
        if (*s == '.') {
            s = sortCount(s + 1, &k->echar, &ok);
            if (!ok) {
                fprintf(stderr, "sort: invalid number after '.': invalid count at start of %s\n", gnuQuoteLocale(s, q, sizeof(q)));
                return SORT_FAILURE;
            }
        }
        s = sortSetOrdering(s, k, 2);
    }
    if (*s) return sortBadSpec("stray character in field spec", spec);
    return 0;
}

static int sortTry(void) {
    fputs("Try 'sort --help' for more information.\n", stderr);
    return SORT_FAILURE;
}

/* GNU's argmatch_die: the valid choices, and status 1, not 2. */
static int sortBadArg(const char *option, const char *val, const char *const *valid, int n) {
    char q[512], q2[64];
    fprintf(stderr, "sort: invalid argument %s for %s\nValid arguments are:\n",
            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale(option, q2, sizeof(q2)));
    for (int i = 0; i < n; i++) {
        /* An entry "a|b" lists two names for one choice. */
        char one[64];
        const char *bar = strchr(valid[i], '|');
        if (bar) {
            snprintf(one, sizeof(one), "%.*s", (int)(bar - valid[i]), valid[i]);
            fprintf(stderr, "  - %s", gnuQuoteLocale(one, q, sizeof(q)));
            fprintf(stderr, ", %s\n", gnuQuoteLocale(bar + 1, q, sizeof(q)));
        } else {
            fprintf(stderr, "  - %s\n", gnuQuoteLocale(valid[i], q, sizeof(q)));
        }
    }
    fputs("Try 'sort --help' for more information.\n", stderr);
    return 1;
}

static void sortUsage(void) {
    fputs("Usage: sort [OPTION]... [FILE]...\n"
          "  or:  sort [OPTION]... --files0-from=F\n"
          "Write sorted concatenation of all FILE(s) to standard output.\n"
          "\n"
          "With no FILE, or when FILE is -, read standard input.\n"
          "\n"
          "Ordering options:\n"
          "  -b, --ignore-leading-blanks  ignore leading blanks\n"
          "  -d, --dictionary-order      consider only blanks and alphanumeric characters\n"
          "  -f, --ignore-case           fold lower case to upper case characters\n"
          "  -g, --general-numeric-sort  compare according to general numerical value\n"
          "  -i, --ignore-nonprinting    consider only printable characters\n"
          "  -M, --month-sort            compare (unknown) < 'JAN' < ... < 'DEC'\n"
          "  -h, --human-numeric-sort    compare human readable numbers (e.g., 2K 1G)\n"
          "  -n, --numeric-sort          compare according to string numerical value\n"
          "  -R, --random-sort           shuffle, but group identical keys\n"
          "      --random-source=FILE    get random bytes from FILE\n"
          "  -r, --reverse               reverse the result of comparisons\n"
          "      --sort=WORD             sort according to WORD:\n"
          "                                general-numeric -g, human-numeric -h, month -M,\n"
          "                                numeric -n, random -R, version -V\n"
          "  -V, --version-sort          natural sort of (version) numbers within text\n"
          "\n"
          "Other options:\n"
          "  -c, --check, --check=diagnose-first  check for sorted input; do not sort\n"
          "  -C, --check=quiet, --check=silent  like -c, but do not report first bad line\n"
          "      --files0-from=F       read input from the files specified by\n"
          "                            NUL-terminated names in file F\n"
          "  -k, --key=KEYDEF          sort via a key; KEYDEF gives location and type\n"
          "  -m, --merge               merge already sorted files; do not sort\n"
          "  -o, --output=FILE         write result to FILE instead of standard output\n"
          "  -s, --stable              stabilize sort by disabling last-resort comparison\n"
          "  -t, --field-separator=SEP  use SEP instead of non-blank to blank transition\n"
          "  -u, --unique              output only the first of lines with equal keys\n"
          "  -z, --zero-terminated     line delimiter is NUL, not newline\n"
          "  -S, -T, --parallel, --batch-size, --compress-program: accepted, unused\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n"
          "\n"
          "KEYDEF is F[.C][OPTS][,F[.C][OPTS]] for start and stop position, where F is a\n"
          "field number and C a character position in the field; both are origin 1, and\n"
          "the stop position defaults to the line's end. OPTS is one or more single-letter\n"
          "ordering options [bdfgiMhnRrV], which override global ordering options for\n"
          "that key. If no key is given, use the entire line as the key.\n",
          stdout);
}

typedef struct {
    const char *name;
    char shortEq;    /* the short option it means, or 0 */
    int arg;         /* 0 none, 1 required, 2 optional */
} SortLong;

static const SortLong sortLongs[] = {
    {"batch-size", 0, 1}, {"buffer-size", 'S', 1}, {"check", 'c', 2}, {"compress-program", 0, 1},
    {"debug", 0, 0}, {"dictionary-order", 'd', 0}, {"field-separator", 't', 1}, {"files0-from", 0, 1},
    {"general-numeric-sort", 'g', 0}, {"help", 0, 0}, {"human-numeric-sort", 'h', 0},
    {"ignore-case", 'f', 0}, {"ignore-leading-blanks", 'b', 0}, {"ignore-nonprinting", 'i', 0},
    {"key", 'k', 1}, {"merge", 'm', 0}, {"month-sort", 'M', 0}, {"numeric-sort", 'n', 0},
    {"output", 'o', 1}, {"parallel", 0, 1}, {"random-sort", 'R', 0}, {"random-source", 0, 1},
    {"reverse", 'r', 0}, {"sort", 0, 1}, {"stable", 's', 0}, {"temporary-directory", 'T', 1},
    {"unique", 'u', 0}, {"version", 0, 0}, {"version-sort", 'V', 0}, {"zero-terminated", 'z', 0},
};

typedef struct {
    SortKey global;
    SortKey *keys;
    size_t nkeys;
    int tab;
    bool unique, stable, merge, debug;
    int check;              /* 0, 'c', 'C' */
    const char *output, *files0, *randomSource;
    char delim;
} SortOptions;

/* Applies one option (short letter, or a long one by name); returns 0,
 * or an exit status after a message. */
static int sortOption(SortOptions *o, char c, const char *longName, const char *val) {
    char q[512];
    switch (c) {
    case 'b': case 'd': case 'f': case 'g': case 'h': case 'i': case 'M': case 'n': case 'R': case 'r': case 'V': {
        char s[2] = {c, '\0'};
        sortSetOrdering(s, &o->global, 0);
        return 0;
    }
    case 'c': case 'C':
        if (c == 'c' && val) {
            if (!strcmp(val, "quiet") || !strcmp(val, "silent")) c = 'C';
            else if (strcmp(val, "diagnose-first")) {
                static const char *const valid[] = {"quiet|silent", "diagnose-first"};
                return sortBadArg("--check", val, valid, 2);
            }
        }
        if (o->check && o->check != c) {
            fputs("sort: options '-cC' are incompatible\n", stderr);
            return SORT_FAILURE;
        }
        o->check = c;
        return 0;
    case 'k': {
        SortKey k;
        int r = sortParseKey(val, &k);
        if (r) return r;
        SortKey *nk = (SortKey *)realloc(o->keys, (o->nkeys + 1) * sizeof(SortKey));
        if (!nk) return SORT_FAILURE;
        o->keys = nk;
        o->keys[o->nkeys++] = k;
        return 0;
    }
    case 'm': o->merge = true; return 0;
    case 'o':
        if (o->output && strcmp(o->output, val)) {
            fputs("sort: multiple output files specified\n", stderr);
            return SORT_FAILURE;
        }
        o->output = val;
        return 0;
    case 's': o->stable = true; return 0;
    case 'S': case 'T': return 0;
    case 't': {
        int t;
        if (!val[0]) {
            fputs("sort: empty tab\n", stderr);
            return SORT_FAILURE;
        }
        if (val[1] == '\0') {
            t = (unsigned char)val[0];
        } else if (!strcmp(val, "\\0")) {
            t = '\0';
        } else {
            fprintf(stderr, "sort: multi-character tab %s\n", gnuQuoteLocale(val, q, sizeof(q)));
            return SORT_FAILURE;
        }
        if (o->tab >= 0 && o->tab != t) {
            fputs("sort: incompatible tabs\n", stderr);
            return SORT_FAILURE;
        }
        o->tab = t;
        return 0;
    }
    case 'u': o->unique = true; return 0;
    case 'z': o->delim = '\0'; return 0;
    default: break;
    }
    if (!longName) return 0;
    if (!strcmp(longName, "files0-from")) o->files0 = val;
    else if (!strcmp(longName, "random-source")) o->randomSource = val;
    else if (!strcmp(longName, "debug")) o->debug = true;
    else if (!strcmp(longName, "sort")) {
        static const char *const words[] = {"general-numeric", "human-numeric", "month", "numeric", "random", "version"};
        static const char letters[] = "ghMnRV";
        for (int i = 0; i < 6; i++)
            if (!strcmp(val, words[i])) return sortOption(o, letters[i], NULL, NULL);
        return sortBadArg("--sort", val, words, 6);
    }
    return 0;   /* batch-size, compress-program, parallel: no effect here */
}

static bool sortWriteLine(FILE *out, const SortLine *l, char delim) {
    return fwrite(l->text, 1, l->len, out) == l->len && putc(delim, out) != EOF;
}

int smallclueSortCommand(int argc, char **argv) {
    SortOptions o;
    memset(&o, 0, sizeof(o));
    o.tab = -1;
    o.delim = '\n';
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    size_t nfiles = 0;
    int status = 0;
    SortCtx x;
    memset(&x, 0, sizeof(x));
    SortBuffers keep = {NULL, 0};
    SortLines lines = {NULL, 0, 0};
    SortLines *perFile = NULL;
    char *files0data = NULL;
    FILE *out = stdout;
    if (!files) return SORT_FAILURE;

    bool endOfOptions = false;
    for (int i = 1; i < argc; i++) {
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
            const SortLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(sortLongs) / sizeof(sortLongs[0]); k++) {
                if (strncmp(sortLongs[k].name, opt, len)) continue;
                if (strlen(sortLongs[k].name) == len) { m = &sortLongs[k]; matches = 1; break; }
                m = &sortLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "sort: option '%s' is ambiguous\n" : "sort: unrecognized option '%s'\n", arg);
                status = sortTry();
                goto done;
            }
            if (m->arg == 1 && !val) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "sort: option '--%s' requires an argument\n", m->name);
                    status = sortTry();
                    goto done;
                }
                val = argv[++i];
            }
            if (m->arg == 0 && val) {
                fprintf(stderr, "sort: option '--%s' doesn't allow an argument\n", m->name);
                status = sortTry();
                goto done;
            }
            if (!strcmp(m->name, "help")) { sortUsage(); goto done; }
            if (!strcmp(m->name, "version")) { puts("sort (SmallCLUE) 9.4"); goto done; }
            if ((status = sortOption(&o, m->shortEq, m->name, val)) != 0) goto done;
            continue;
        }
        for (const char *c = arg + 1; *c; c++) {
            if (strchr("koStTy", *c)) {
                const char *val = c[1] ? c + 1 : NULL;
                if (!val) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "sort: option requires an argument -- '%c'\n", *c);
                        status = sortTry();
                        goto done;
                    }
                    val = argv[++i];
                }
                if (*c != 'y' && (status = sortOption(&o, *c, NULL, val)) != 0) goto done;
                break;
            }
            if (!strchr("bcCdfghiMmnRrsuVz", *c)) {
                fprintf(stderr, "sort: invalid option -- '%c'\n", *c);
                status = sortTry();
                goto done;
            }
            if ((status = sortOption(&o, *c, NULL, NULL)) != 0) goto done;
        }
    }
    if (o.debug) {
        fputs("sort: --debug is not supported by this sort\n", stderr);
        status = SORT_FAILURE;
        goto done;
    }

    /* Keys without ordering options take the global ones; with no key, a
     * global option makes the whole line one. */
    for (size_t i = 0; i < o.nkeys; i++) {
        SortKey *k = &o.keys[i];
        if (sortKeyIsDefault(k) && !k->reverse) {
            k->ignore = o.global.ignore;
            k->translate = o.global.translate;
            k->skipsblanks = o.global.skipsblanks;
            k->skipeblanks = o.global.skipeblanks;
            k->numeric = o.global.numeric;
            k->general = o.global.general;
            k->human = o.global.human;
            k->month = o.global.month;
            k->version = o.global.version;
            k->random = o.global.random;
            k->reverse = o.global.reverse;
        }
    }
    if (o.nkeys == 0 && !sortKeyIsDefault(&o.global)) {
        o.keys = (SortKey *)malloc(sizeof(SortKey));
        if (!o.keys) { status = SORT_FAILURE; goto done; }
        o.keys[0] = o.global;
        o.keys[0].sword = SORT_NOEND;
        o.keys[0].schar = 0;
        o.keys[0].eword = SORT_NOEND;
        o.keys[0].echar = 0;
        o.nkeys = 1;
    }
    for (size_t i = 0; i < o.nkeys; i++) {
        SortKey *k = &o.keys[i];
        if (k->numeric + k->general + k->human + k->month + (k->version || k->random || k->ignore) > 1) {
            SortKey t = *k;
            char opts[16];
            t.skipsblanks = t.skipeblanks = t.reverse = false;
            sortKeyOpts(&t, opts);
            fprintf(stderr, "sort: options '-%s' are incompatible\n", opts);
            status = SORT_FAILURE;
            goto done;
        }
    }
    if (o.check && o.output) {
        fprintf(stderr, "sort: options '-%co' are incompatible\n", o.check);
        status = SORT_FAILURE;
        goto done;
    }

    if (o.files0) {
        char q[4096];
        if (nfiles) {
            fprintf(stderr, "sort: extra operand %s\nfile operands cannot be combined with --files0-from\n",
                    gnuQuoteLocale(files[0], q, sizeof(q)));
            status = sortTry();
            goto done;
        }
        SortLines names = {NULL, 0, 0};
        if (!sortRead(o.files0, '\0', &keep, &names)) { status = SORT_FAILURE; goto done; }
        char **nf = (char **)realloc(files, (names.n + 1) * sizeof(char *));
        if (!nf) { free(names.v); status = SORT_FAILURE; goto done; }
        files = nf;
        for (size_t i = 0; i < names.n; i++) {
            if (names.v[i].len == 0) {
                fprintf(stderr, "sort: %s:%zu: invalid zero-length file name\n",
                        gnuQuoteMaybe(o.files0, q, sizeof(q)), i + 1);
                free(names.v);
                status = SORT_FAILURE;
                goto done;
            }
            files[nfiles] = strndup(names.v[i].text, names.v[i].len);
            if (!files[nfiles]) break;
            nfiles++;
        }
        files0data = (char *)1; /* files[] entries are ours to free */
        free(names.v);
    }
    if (nfiles == 0 && o.files0) {
        char q[4096];
        fprintf(stderr, "sort: no input from %s\n", gnuQuote(o.files0, q, sizeof(q)));
        status = SORT_FAILURE;
        goto done;
    }
    if (nfiles == 0) files[nfiles++] = (char *)"-";
    if (o.check && nfiles > 1) {
        char q[4096];
        fprintf(stderr, "sort: extra operand %s not allowed with -%c\n", gnuQuote(files[1], q, sizeof(q)), o.check);
        status = SORT_FAILURE;
        goto done;
    }

    x.keys = o.keys;
    x.nkeys = o.nkeys;
    x.reverse = o.global.reverse;
    x.unique = o.unique;
    x.stable = o.stable;
    x.tab = o.tab;
    {
        unsigned char seed[8] = {0};
        bool seeded = false;
        const char *src = o.randomSource ? o.randomSource : "/dev/urandom";
        int fd = open(src, O_RDONLY);
        if (fd >= 0) {
            seeded = read(fd, seed, sizeof(seed)) > 0;
            close(fd);
        } else if (o.randomSource) {
            sortDie("open failed", o.randomSource, errno);
            status = SORT_FAILURE;
            goto done;
        }
        memcpy(&x.seed, seed, sizeof(x.seed));
        if (!seeded) x.seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    }

    if (o.merge && !o.check) {
        perFile = (SortLines *)calloc(nfiles, sizeof(SortLines));
        if (!perFile) { status = SORT_FAILURE; goto done; }
        for (size_t i = 0; i < nfiles; i++)
            if (!sortRead(files[i], o.delim, &keep, &perFile[i])) { status = SORT_FAILURE; goto done; }
    } else {
        for (size_t i = 0; i < nfiles; i++)
            if (!sortRead(files[i], o.delim, &keep, &lines)) { status = SORT_FAILURE; goto done; }
    }

    if (o.check) {
        for (size_t i = 1; i < lines.n; i++) {
            int cmp = sortCompare(&x, &lines.v[i - 1], &lines.v[i]);
            if (cmp > 0 || (o.unique && cmp == 0)) {
                if (o.check == 'c') {
                    fprintf(stderr, "sort: %s:%zu: disorder: ", files[0], i + 1);
                    fwrite(lines.v[i].text, 1, lines.v[i].len, stderr);
                    fputc('\n', stderr);
                }
                status = 1;
                break;
            }
        }
        goto done;
    }

    /* Output is opened only now, so `sort -o f f` reads f first. */
    if (o.output) {
        out = fopen(o.output, "w");
        if (!out) {
            sortDie("open failed", o.output, errno);
            out = stdout;
            status = SORT_FAILURE;
            goto done;
        }
    }

    const SortLine *last = NULL;
    if (perFile) {
        size_t *pos = (size_t *)calloc(nfiles, sizeof(size_t));
        if (!pos) { status = SORT_FAILURE; goto done; }
        for (;;) {
            size_t best = SIZE_MAX;
            for (size_t f = 0; f < nfiles; f++) {
                if (pos[f] >= perFile[f].n) continue;
                if (best == SIZE_MAX || sortCompare(&x, &perFile[f].v[pos[f]], &perFile[best].v[pos[best]]) < 0)
                    best = f;
            }
            if (best == SIZE_MAX) break;
            const SortLine *l = &perFile[best].v[pos[best]++];
            if (o.unique && last && sortCompare(&x, last, l) == 0) continue;
            if (!sortWriteLine(out, l, o.delim)) break;
            last = l;
        }
        free(pos);
    } else {
        if (lines.n > 1) {
            SortLine *tmp = (SortLine *)malloc(lines.n * sizeof(SortLine));
            if (!tmp) { status = SORT_FAILURE; goto done; }
            sortMerge(&x, lines.v, tmp, lines.n);
            free(tmp);
        }
        for (size_t i = 0; i < lines.n; i++) {
            if (o.unique && last && sortCompare(&x, last, &lines.v[i]) == 0) continue;
            if (!sortWriteLine(out, &lines.v[i], o.delim)) break;
            last = &lines.v[i];
        }
    }

done:
    if (out != stdout) {
        if (fclose(out) != 0 && status == 0) {
            sortDie("write failed", o.output, errno);
            status = SORT_FAILURE;
        }
    }
    if (fflush(stdout) != 0 || ferror(stdout)) {
        if (errno != EPIPE) fprintf(stderr, "sort: write failed: 'standard output': %s\n", strerror(errno));
        if (status == 0) status = SORT_FAILURE;
    }
    if (perFile) {
        for (size_t i = 0; i < nfiles; i++) free(perFile[i].v);
        free(perFile);
    }
    if (files0data)
        for (size_t i = 0; i < nfiles; i++) free(files[i]);
    for (size_t i = 0; i < keep.n; i++) free(keep.bufs[i]);
    free(keep.bufs);
    free(lines.v);
    free(o.keys);
    free(x.buf[0]);
    free(x.buf[1]);
    free(files);
    return status;
}
