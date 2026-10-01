/*
 * diff: compare files line by line, compatible with GNU diffutils 3.10.
 *
 * The diff this replaces printed only unified diffs, from an O(n*m)
 * longest-common-subsequence table, so its default output was not diff's
 * default output, its hunks were not the ones GNU picks, and it had no -r,
 * -c, -q, -N or whitespace options. This chooses the same edit script as
 * GNU: equivalence classes for lines (under -i -b -w -E -Z
 * --strip-trailing-cr), the common prefix and suffix set aside,
 * discard_confusing_lines, gnulib's diffseq (Myers' middle snake, with the
 * cost cutoff past which GNU settles for a good-enough split), and
 * shift_boundaries; then prints it in GNU's normal, context (-c/-C),
 * unified (-u/-U), ed (-e) or RCS (-n) form, with -p function lines, -t/-T,
 * -B and -I ignorable changes, binary detection, labels, "\ No newline at
 * end of file", -q/-s, and directory comparison (-r, -N, -x/-X, "Only in",
 * "Common subdirectories", the "diff OPTIONS a/f b/f" lines).
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "diff_app.h"
#include "app_hooks.h"
#include "gnu_regex.h"
#include "gnu_util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define DIFF_MTIM(st) ((st)->st_mtimespec)
#else
#define DIFF_MTIM(st) ((st)->st_mtim)
#endif

typedef long lin;

enum { OUT_NORMAL, OUT_CONTEXT, OUT_UNIFIED, OUT_ED, OUT_RCS, OUT_SIDE };

typedef struct {
    /* options */
    int format;
    int styleSet;            /* the style an option chose, to catch conflicts */
    bool styleConflict;
    lin context;
    long width;              /* -W */
    bool leftColumn, suppressCommon;
    bool brief, reportSame, recursive, newFile, unidirectionalNew, text, minimal;
    bool ignoreCase, ignoreAllSpace, ignoreSpaceChange, ignoreTabExpansion, ignoreTrailingSpace, stripCr;
    bool ignoreBlank, expandTabs, initialTab, showFunction;
    regex_t *ignoreRe;
    size_t nIgnoreRe;
    regex_t funcRe;
    bool haveFuncRe;
    const char *label[2];
    int nlabels;
    char **exclude;
    size_t nexclude;
    int tabSize;
    char *switches;          /* "-r -u", for "diff -r -u a/f b/f" */
    /* state */
    int status;              /* 0 same, 1 differ, 2 trouble */
} Diff;

typedef struct {
    char *data;
    size_t size;
    const char **line;       /* start of each line */
    size_t *len;             /* without the newline */
    lin nlines;
    bool missingNewline;     /* the last line has none */
    bool binary;
    const char *name;        /* as printed */
    struct stat st;
} DiffFile;

typedef struct DiffChange {
    lin line0, line1, deleted, inserted;
    bool ignore;
    struct DiffChange *next;
} DiffChange;

/* --- Reading. --- */

static bool diffRead(Diff *d, const char *path, DiffFile *f) {
    memset(f, 0, sizeof(*f));
    f->name = path;
    int fd = 0;
    FILE *fp = NULL;
    if (strcmp(path, "-")) {
        fp = smallclueAppOpenRead(path);
        if (!fp) return false;
        fd = fileno(fp);
    }
    if (fstat(fd, &f->st) != 0) {
        if (fp) fclose(fp);
        return false;
    }
    if (!strcmp(path, "-")) clock_gettime(CLOCK_REALTIME, &DIFF_MTIM(&f->st));
    size_t cap = 65536;
    f->data = (char *)malloc(cap + 1);
    for (;;) {
        if (!f->data) break;
        if (f->size == cap) {
            char *v = (char *)realloc(f->data, cap * 2 + 1);
            if (!v) break;
            f->data = v;
            cap *= 2;
        }
        ssize_t n = read(fd, f->data + f->size, cap - f->size);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            int e = errno;
            if (fp) fclose(fp);
            errno = e;
            return false;
        }
        if (n == 0) break;
        f->size += (size_t)n;
    }
    if (fp) fclose(fp);
    if (!f->data) { errno = ENOMEM; return false; }
    f->data[f->size] = '\0';
    if (!d->text) {
        size_t probe = f->size < 65536 ? f->size : 65536;
        f->binary = memchr(f->data, '\0', probe) != NULL;
    }
    size_t cap2 = 1024;
    f->line = (const char **)malloc(cap2 * sizeof(char *));
    f->len = (size_t *)malloc(cap2 * sizeof(size_t));
    size_t start = 0;
    for (size_t i = 0; i <= f->size; i++) {
        if (i == f->size || f->data[i] == '\n') {
            if (i == f->size && i == start) break;
            if ((size_t)f->nlines == cap2) {
                cap2 *= 2;
                f->line = (const char **)realloc(f->line, cap2 * sizeof(char *));
                f->len = (size_t *)realloc(f->len, cap2 * sizeof(size_t));
                if (!f->line || !f->len) { errno = ENOMEM; return false; }
            }
            f->line[f->nlines] = f->data + start;
            f->len[f->nlines] = i - start;
            f->nlines++;
            if (i == f->size) f->missingNewline = true;
            start = i + 1;
        }
    }
    return true;
}

static void diffFreeFile(DiffFile *f) {
    free(f->data);
    free(f->line);
    free(f->len);
}

/* --- Equivalence classes. --- */

/* The line as the options compare it. */
static size_t diffNormalize(const Diff *d, const char *s, size_t n, char *out) {
    size_t o = 0;
    if (d->stripCr && n && s[n - 1] == '\r') n--;
    if (d->ignoreTrailingSpace || d->ignoreSpaceChange)
        while (n && isspace((unsigned char)s[n - 1])) n--;
    size_t col = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (d->ignoreAllSpace && isspace(c)) continue;
        if (d->ignoreSpaceChange && isspace(c)) {
            if (o == 0 || out[o - 1] != ' ' || (i > 0 && !isspace((unsigned char)s[i - 1]))) {
                while (i + 1 < n && isspace((unsigned char)s[i + 1])) i++;
                out[o++] = ' ';
            }
            continue;
        }
        if (d->ignoreTabExpansion && c == '\t') {
            size_t spaces = (size_t)d->tabSize - col % (size_t)d->tabSize;
            for (size_t k = 0; k < spaces; k++) out[o++] = ' ';
            col += spaces;
            continue;
        }
        out[o++] = (char)(d->ignoreCase ? tolower(c) : c);
        col++;
    }
    return o;
}

typedef struct {
    char *key;
    size_t len;
    lin cls;
} DiffBucketEntry;

typedef struct {
    DiffBucketEntry *v;
    size_t cap, n;
    lin next;
} DiffClasses;

static uint64_t diffHash(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static lin diffClassOf(DiffClasses *c, const char *s, size_t n) {
    if (c->n * 2 >= c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 4096;
        DiffBucketEntry *v = (DiffBucketEntry *)calloc(cap, sizeof(DiffBucketEntry));
        if (!v) return -1;
        for (size_t i = 0; i < c->cap; i++) {
            if (!c->v[i].key) continue;
            size_t h = diffHash(c->v[i].key, c->v[i].len) & (cap - 1);
            while (v[h].key) h = (h + 1) & (cap - 1);
            v[h] = c->v[i];
        }
        free(c->v);
        c->v = v;
        c->cap = cap;
    }
    size_t h = diffHash(s, n) & (c->cap - 1);
    while (c->v[h].key) {
        if (c->v[h].len == n && !memcmp(c->v[h].key, s, n)) return c->v[h].cls;
        h = (h + 1) & (c->cap - 1);
    }
    c->v[h].key = (char *)malloc(n + 1);
    if (!c->v[h].key) return -1;
    memcpy(c->v[h].key, s, n);
    c->v[h].key[n] = '\0';
    c->v[h].len = n;
    c->v[h].cls = ++c->next;
    c->n++;
    return c->v[h].cls;
}

/* --- The edit script: diffseq and analyze.c. --- */

typedef struct {
    const lin *xv, *yv;
    lin *fdiag, *bdiag;
    char *xchanged, *ychanged;
    const lin *xreal, *yreal;
    lin tooExpensive;
} DiffCtx;

typedef struct {
    lin xmid, ymid;
    bool loMinimal, hiMinimal;
} DiffPart;

static void diffDiag(lin xoff, lin xlim, lin yoff, lin ylim, bool findMinimal, DiffPart *part, DiffCtx *c) {
    lin *const fd = c->fdiag, *const bd = c->bdiag;
    const lin *const xv = c->xv, *const yv = c->yv;
    const lin dmin = xoff - ylim, dmax = xlim - yoff;
    const lin fmid = xoff - yoff, bmid = xlim - ylim;
    lin fmin = fmid, fmax = fmid, bmin = bmid, bmax = bmid;
    bool odd = (fmid - bmid) & 1;
    fd[fmid] = xoff;
    bd[bmid] = xlim;
    for (lin cost = 1;; ++cost) {
        lin d;
        if (fmin > dmin) fd[--fmin - 1] = -1;
        else ++fmin;
        if (fmax < dmax) fd[++fmax + 1] = -1;
        else --fmax;
        for (d = fmax; d >= fmin; d -= 2) {
            lin tlo = fd[d - 1], thi = fd[d + 1];
            lin x0 = tlo < thi ? thi : tlo + 1;
            lin x, y;
            for (x = x0, y = x0 - d; x < xlim && y < ylim && xv[x] == yv[y]; x++, y++) {}
            fd[d] = x;
            if (odd && bmin <= d && d <= bmax && bd[d] <= x) {
                part->xmid = x;
                part->ymid = y;
                part->loMinimal = part->hiMinimal = true;
                return;
            }
        }
        if (bmin > dmin) bd[--bmin - 1] = LONG_MAX;
        else ++bmin;
        if (bmax < dmax) bd[++bmax + 1] = LONG_MAX;
        else --bmax;
        for (d = bmax; d >= bmin; d -= 2) {
            lin tlo = bd[d - 1], thi = bd[d + 1];
            lin x0 = tlo < thi ? tlo : thi - 1;
            lin x, y;
            for (x = x0, y = x0 - d; xoff < x && yoff < y && xv[x - 1] == yv[y - 1]; x--, y--) {}
            bd[d] = x;
            if (!odd && fmin <= d && d <= fmax && x <= fd[d]) {
                part->xmid = x;
                part->ymid = y;
                part->loMinimal = part->hiMinimal = true;
                return;
            }
        }
        if (findMinimal) continue;
        if (cost >= c->tooExpensive) {
            /* Give up: split at the best diagonal found either way. */
            lin fxybest = -1, fxbest = 0, bxybest = LONG_MAX, bxbest = 0;
            for (d = fmax; d >= fmin; d -= 2) {
                lin x = fd[d] < xlim ? fd[d] : xlim;
                lin y = x - d;
                if (ylim < y) { x = ylim + d; y = ylim; }
                if (fxybest < x + y) { fxybest = x + y; fxbest = x; }
            }
            for (d = bmax; d >= bmin; d -= 2) {
                lin x = xoff > bd[d] ? xoff : bd[d];
                lin y = x - d;
                if (y < yoff) { x = yoff + d; y = yoff; }
                if (x + y < bxybest) { bxybest = x + y; bxbest = x; }
            }
            if ((xlim + ylim) - bxybest < fxybest - (xoff + yoff)) {
                part->xmid = fxbest;
                part->ymid = fxybest - fxbest;
                part->loMinimal = true;
                part->hiMinimal = false;
            } else {
                part->xmid = bxbest;
                part->ymid = bxybest - bxbest;
                part->loMinimal = false;
                part->hiMinimal = true;
            }
            return;
        }
    }
}

static void diffCompareSeq(lin xoff, lin xlim, lin yoff, lin ylim, bool findMinimal, DiffCtx *c) {
    const lin *xv = c->xv, *yv = c->yv;
    while (xoff < xlim && yoff < ylim && xv[xoff] == yv[yoff]) { xoff++; yoff++; }
    while (xoff < xlim && yoff < ylim && xv[xlim - 1] == yv[ylim - 1]) { xlim--; ylim--; }
    if (xoff == xlim) {
        while (yoff < ylim) c->ychanged[c->yreal[yoff++]] = 1;
    } else if (yoff == ylim) {
        while (xoff < xlim) c->xchanged[c->xreal[xoff++]] = 1;
    } else {
        DiffPart part;
        diffDiag(xoff, xlim, yoff, ylim, findMinimal, &part, c);
        diffCompareSeq(xoff, part.xmid, yoff, part.ymid, part.loMinimal, c);
        diffCompareSeq(part.xmid, xlim, part.ymid, ylim, part.hiMinimal, c);
    }
}

/* analyze.c's discard_confusing_lines: lines with no match in the other
 * file are left out of the comparison, and runs of lines matching very
 * often too, so that the middle snake is not led astray. */
static void diffDiscard(lin *const equivs[2], const lin n[2], lin maxClass, char *const changed[2], lin *undiscarded[2],
                        lin *realindex[2], lin nondiscarded[2], bool minimal) {
    lin *counts[2];
    counts[0] = (lin *)calloc((size_t)maxClass + 1, sizeof(lin));
    counts[1] = (lin *)calloc((size_t)maxClass + 1, sizeof(lin));
    char *discards[2];
    discards[0] = (char *)calloc((size_t)(n[0] + n[1]) + 1, 1);
    discards[1] = discards[0] + n[0];
    if (!counts[0] || !counts[1] || !discards[0]) {
        free(counts[0]);
        free(counts[1]);
        free(discards[0]);
        for (int f = 0; f < 2; f++) {
            for (lin i = 0; i < n[f]; i++) { undiscarded[f][i] = equivs[f][i]; realindex[f][i] = i; }
            nondiscarded[f] = n[f];
        }
        return;
    }
    for (int f = 0; f < 2; f++)
        for (lin i = 0; i < n[f]; i++) counts[f][equivs[f][i]]++;
    for (int f = 0; f < 2; f++) {
        lin end = n[f];
        char *dis = discards[f];
        lin *other = counts[1 - f];
        lin many = 5;
        lin tem = end / 64;
        while ((tem = tem >> 2) > 0) many *= 2;
        for (lin i = 0; i < end; i++) {
            lin nmatch = other[equivs[f][i]];
            if (nmatch == 0) dis[i] = 1;
            else if (nmatch > many) dis[i] = 2;
        }
    }
    for (int f = 0; f < 2; f++) {
        lin end = n[f];
        char *dis = discards[f];
        for (lin i = 0; i < end; i++) {
            if (dis[i] == 2) {
                dis[i] = 0;
            } else if (dis[i] != 0) {
                lin j, length, provisional = 0;
                for (j = i; j < end; j++) {
                    if (dis[j] == 0) break;
                    if (dis[j] == 2) ++provisional;
                }
                while (j > i && dis[j - 1] == 2) dis[--j] = 0, --provisional;
                length = j - i;
                if (provisional * 4 > length) {
                    while (j > i)
                        if (dis[--j] == 2) dis[j] = 0;
                } else {
                    lin consec, minimum = 1, t = length >> 2;
                    while (0 < (t >>= 2)) minimum <<= 1;
                    minimum++;
                    for (j = 0, consec = 0; j < length; j++) {
                        if (dis[i + j] != 2) consec = 0;
                        else if (minimum == ++consec) j -= consec;
                        else if (minimum < consec) dis[i + j] = 0;
                    }
                    for (j = 0, consec = 0; j < length; j++) {
                        if (j >= 8 && dis[i + j] == 1) break;
                        if (dis[i + j] == 2) consec = 0, dis[i + j] = 0;
                        else if (dis[i + j] == 0) consec = 0;
                        else consec++;
                        if (consec == 3) break;
                    }
                    i += length - 1;
                    for (j = 0, consec = 0; j < length; j++) {
                        if (j >= 8 && dis[i - j] == 1) break;
                        if (dis[i - j] == 2) consec = 0, dis[i - j] = 0;
                        else if (dis[i - j] == 0) consec = 0;
                        else consec++;
                        if (consec == 3) break;
                    }
                }
            }
        }
    }
    for (int f = 0; f < 2; f++) {
        lin j = 0;
        for (lin i = 0; i < n[f]; i++) {
            if (minimal || discards[f][i] == 0) {
                undiscarded[f][j] = equivs[f][i];
                realindex[f][j++] = i;
            } else {
                changed[f][i] = 1;
            }
        }
        nondiscarded[f] = j;
    }
    free(counts[0]);
    free(counts[1]);
    free(discards[0]);
}

/* analyze.c's shift_boundaries: slide each run of changes to merge with
 * its neighbours and to line up with the other file's changes. */
static void diffShift(char *const changed[2], lin *const equivs[2], const lin n[2]) {
    for (int f = 0; f < 2; f++) {
        char *ch = changed[f];
        char *other = changed[1 - f];
        const lin *eq = equivs[f];
        lin i = 0, j = 0, iEnd = n[f];
        for (;;) {
            lin runlength, start, corresponding;
            while (i < iEnd && !ch[i]) {
                while (other[j++]) {}
                i++;
            }
            if (i == iEnd) break;
            start = i;
            while (ch[++i]) {}
            while (other[j]) j++;
            do {
                runlength = i - start;
                while (start && eq[start - 1] == eq[i - 1]) {
                    ch[--start] = 1;
                    ch[--i] = 0;
                    while (ch[start - 1]) start--;
                    while (other[--j]) {}
                }
                corresponding = other[j - 1] ? i : iEnd;
                while (i != iEnd && eq[start] == eq[i]) {
                    ch[start++] = 0;
                    ch[i++] = 1;
                    while (ch[i]) i++;
                    while (other[++j]) corresponding = i;
                }
            } while (runlength != i - start);
            while (corresponding < i) {
                ch[--start] = 1;
                ch[--i] = 0;
                while (other[--j]) {}
            }
        }
    }
}

/* The changes between a and b, forward order; NULL when identical. */
static DiffChange *diffScript(Diff *d, DiffFile *a, DiffFile *b, DiffClasses *cls) {
    lin n0 = a->nlines, n1 = b->nlines;
    lin *eq0 = (lin *)malloc(((size_t)n0 + 1) * sizeof(lin));
    lin *eq1 = (lin *)malloc(((size_t)n1 + 1) * sizeof(lin));
    size_t maxLen = 0;
    for (lin i = 0; i < n0; i++) if (a->len[i] > maxLen) maxLen = a->len[i];
    for (lin i = 0; i < n1; i++) if (b->len[i] > maxLen) maxLen = b->len[i];
    char *norm = (char *)malloc(maxLen * (size_t)(d->tabSize > 0 ? d->tabSize : 8) + 2);
    if (!eq0 || !eq1 || !norm) { free(eq0); free(eq1); free(norm); return NULL; }
    /* A last line without its newline is a different line, as in GNU,
     * unless the options ignore whitespace at the end of lines. */
    bool nlMatters = !(d->ignoreAllSpace || d->ignoreSpaceChange || d->ignoreTrailingSpace) && d->format != OUT_ED;
    for (int f = 0; f < 2; f++) {
        DiffFile *df = f ? b : a;
        lin *eq = f ? eq1 : eq0;
        for (lin i = 0; i < df->nlines; i++) {
            size_t k = diffNormalize(d, df->line[i], df->len[i], norm);
            if (nlMatters && i == df->nlines - 1 && df->missingNewline) norm[k++] = '\0';
            eq[i] = diffClassOf(cls, norm, k);
        }
    }
    free(norm);
    /* The common prefix and suffix take no part -- found byte for byte, as
     * GNU's find_identical_ends does, and less the "horizon": for context
     * and unified output, that many lines of each stay in the analysis, so
     * a change can slide into them. */
    lin horizon = d->format == OUT_CONTEXT || d->format == OUT_UNIFIED ? d->context : 0;
#define DIFF_RAW_EQ(i, j) (a->len[i] == b->len[j] && !memcmp(a->line[i], b->line[j], a->len[i]) && \
                           ((i == n0 - 1 && a->missingNewline) == (j == n1 - 1 && b->missingNewline)))
    lin pre = 0;
    while (pre < n0 && pre < n1 && DIFF_RAW_EQ(pre, pre)) pre++;
    pre = pre > horizon ? pre - horizon : 0;
    lin suf = 0;
    while (suf < n0 - pre && suf < n1 - pre && DIFF_RAW_EQ(n0 - 1 - suf, n1 - 1 - suf)) suf++;
    suf = suf > horizon ? suf - horizon : 0;
#undef DIFF_RAW_EQ
    lin m[2] = {n0 - pre - suf, n1 - pre - suf};
    char *chMem = (char *)calloc((size_t)(m[0] + m[1]) + 4, 1);
    char *changed[2] = {chMem + 1, chMem + m[0] + 3};
    lin *equivs[2] = {eq0 + pre, eq1 + pre};
    lin *und[2], *real[2], nondis[2];
    und[0] = (lin *)malloc(((size_t)m[0] + 1) * sizeof(lin));
    und[1] = (lin *)malloc(((size_t)m[1] + 1) * sizeof(lin));
    real[0] = (lin *)malloc(((size_t)m[0] + 1) * sizeof(lin));
    real[1] = (lin *)malloc(((size_t)m[1] + 1) * sizeof(lin));
    if (!chMem || !und[0] || !und[1] || !real[0] || !real[1]) {
        free(chMem); free(und[0]); free(und[1]); free(real[0]); free(real[1]); free(eq0); free(eq1);
        return NULL;
    }
    lin maxClass = cls->next;
    diffDiscard(equivs, m, maxClass, changed, und, real, nondis, d->minimal);
    lin diags = nondis[0] + nondis[1] + 3;
    lin *fdiag = (lin *)malloc((size_t)diags * 2 * sizeof(lin));
    if (fdiag) {
        DiffCtx c;
        c.xv = und[0];
        c.yv = und[1];
        c.fdiag = fdiag + nondis[1] + 1;
        c.bdiag = c.fdiag + diags;
        c.xchanged = changed[0];
        c.ychanged = changed[1];
        c.xreal = real[0];
        c.yreal = real[1];
        c.tooExpensive = 1;
        for (lin t = diags; t != 0; t >>= 2) c.tooExpensive <<= 1;
        if (c.tooExpensive < 4096) c.tooExpensive = 4096;
        diffCompareSeq(0, nondis[0], 0, nondis[1], d->minimal, &c);
        free(fdiag);
    }
    diffShift(changed, equivs, m);
    /* build_script, walking back so the list comes out forward */
    DiffChange *script = NULL;
    lin i0 = m[0], i1 = m[1];
    while (i0 >= 0 || i1 >= 0) {
        if (changed[0][i0 - 1] | changed[1][i1 - 1]) {
            lin l0 = i0, l1 = i1;
            while (changed[0][i0 - 1]) --i0;
            while (changed[1][i1 - 1]) --i1;
            DiffChange *c = (DiffChange *)calloc(1, sizeof(DiffChange));
            if (c) {
                c->line0 = i0 + pre;
                c->line1 = i1 + pre;
                c->deleted = l0 - i0;
                c->inserted = l1 - i1;
                c->next = script;
                script = c;
            }
        }
        i0--;
        i1--;
    }
    free(chMem); free(und[0]); free(und[1]); free(real[0]); free(real[1]); free(eq0); free(eq1);
    return script;
}

static void diffFreeScript(DiffChange *c) {
    while (c) {
        DiffChange *n = c->next;
        free(c);
        c = n;
    }
}

/* -B and -I: a change whose every line is blank (or matches) is ignorable. */
static bool diffIgnorableLine(const Diff *d, const DiffFile *f, lin i) {
    const char *s = f->line[i];
    size_t n = f->len[i];
    if (d->ignoreBlank) {
        /* Blank means empty once the whitespace options have had their say:
         * "   " is blank under -b, -w or -Z, not otherwise (GNU's -B). */
        size_t k = n;
        if (d->stripCr && k && s[k - 1] == '\r') k--;
        if (d->ignoreAllSpace || d->ignoreSpaceChange || d->ignoreTrailingSpace)
            while (k && isspace((unsigned char)s[k - 1])) k--;
        if (k == 0) return true;
    }
    for (size_t r = 0; r < d->nIgnoreRe; r++) {
        regmatch_t m[1];
        m[0].rm_so = 0;
        m[0].rm_eo = (regoff_t)n;
        if (regexec(&d->ignoreRe[r], s, 1, m, REG_STARTEND) == 0) return true;
    }
    return false;
}

static void diffMarkIgnorable(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    if (!d->ignoreBlank && !d->nIgnoreRe) return;
    for (DiffChange *c = script; c; c = c->next) {
        bool all = true;
        for (lin i = c->line0; all && i < c->line0 + c->deleted; i++) all = diffIgnorableLine(d, a, i);
        for (lin i = c->line1; all && i < c->line1 + c->inserted; i++) all = diffIgnorableLine(d, b, i);
        c->ignore = all;
    }
}

/* --- Output. --- */

/* One output line. `flag` is GNU's line flag ("<", ">", "!", "+", "-",
 * " "); it is followed by a space, or a tab under -T. In unified output
 * the flag stands alone, and -T puts a tab after it -- in place of it, for
 * context lines -- as GNU's pr_unidiff_hunk does. */
static void diffLine(const Diff *d, const char *flag, const DiffFile *f, lin i) {
    if (d->format == OUT_UNIFIED) {
        if (flag[0] == ' ') putchar(d->initialTab ? '\t' : ' ');
        else {
            putchar(flag[0]);
            if (d->initialTab) putchar('\t');
        }
    } else {
        fputs(flag, stdout);
        putchar(d->initialTab ? '\t' : ' ');
    }
    if (d->expandTabs) {
        size_t col = 0;
        for (size_t k = 0; k < f->len[i]; k++) {
            char c = f->line[i][k];
            if (c == '\t') {
                size_t sp = (size_t)d->tabSize - col % (size_t)d->tabSize;
                for (size_t s2 = 0; s2 < sp; s2++) putchar(' ');
                col += sp;
            } else {
                putchar(c);
                col++;
            }
        }
    } else {
        fwrite(f->line[i], 1, f->len[i], stdout);
    }
    putchar('\n');
    if (i == f->nlines - 1 && f->missingNewline) fputs("\\ No newline at end of file\n", stdout);
}

static void diffRange(lin a, lin b, char sep) {
    /* 0-based a..b inclusive, as GNU's print_number_range */
    lin ta = a + 1, tb = b + 1;
    if (tb <= ta) printf("%ld", tb);
    else printf("%ld%c%ld", ta, sep, tb);
}

static void diffNormal(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    for (DiffChange *c = script; c; c = c->next) {
        if (c->ignore) continue;
        lin f0 = c->line0, l0 = c->line0 + c->deleted - 1, f1 = c->line1, l1 = c->line1 + c->inserted - 1;
        diffRange(f0, l0, ',');
        putchar(!c->inserted ? 'd' : !c->deleted ? 'a' : 'c');
        diffRange(f1, l1, ',');
        putchar('\n');
        for (lin i = f0; i <= l0; i++) diffLine(d, "<", a, i);
        if (c->deleted && c->inserted) fputs("---\n", stdout);
        for (lin i = f1; i <= l1; i++) diffLine(d, ">", b, i);
    }
}

static void diffEd(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    (void)a;
    /* ed applies them last first */
    size_t n = 0;
    for (DiffChange *c = script; c; c = c->next) n++;
    DiffChange **v = (DiffChange **)malloc(n * sizeof(DiffChange *));
    if (!v) return;
    size_t k = 0;
    for (DiffChange *c = script; c; c = c->next) v[k++] = c;
    while (k-- > 0) {
        DiffChange *c = v[k];
        if (c->ignore) continue;
        lin f0 = c->line0, l0 = c->line0 + c->deleted - 1;
        diffRange(f0, l0, ',');
        putchar(!c->inserted ? 'd' : !c->deleted ? 'a' : 'c');
        putchar('\n');
        if (c->inserted) {
            /* A lone "." would end the text: GNU writes "..", leaves insert
             * mode, strips the extra dot, and appends again only if more
             * lines follow. */
            bool insertMode = true;
            for (lin i = c->line1; i < c->line1 + c->inserted; i++) {
                if (!insertMode) {
                    fputs("a\n", stdout);
                    insertMode = true;
                }
                if (b->len[i] == 1 && b->line[i][0] == '.') {
                    fputs("..\n.\ns/.//\n", stdout);
                    insertMode = false;
                    continue;
                }
                fwrite(b->line[i], 1, b->len[i], stdout);
                putchar('\n');
            }
            if (insertMode) fputs(".\n", stdout);
        }
    }
    (void)d;
    free(v);
}

static void diffRcs(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    (void)a;
    (void)d;
    for (DiffChange *c = script; c; c = c->next) {
        if (c->ignore) continue;
        if (c->deleted) printf("d%ld %ld\n", c->line0 + 1, c->deleted);
        if (c->inserted) {
            printf("a%ld %ld\n", c->line0 + c->deleted, c->inserted);
            for (lin i = c->line1; i < c->line1 + c->inserted; i++) {
                fwrite(b->line[i], 1, b->len[i], stdout);
                if (!(i == b->nlines - 1 && b->missingNewline)) putchar('\n');
            }
        }
    }
}

/* --- Side by side (-y): GNU's side.c. --- */

static size_t diffTabTo(const Diff *d, size_t from, size_t to) {
    size_t ts = (size_t)d->tabSize;
    if (!d->expandTabs)
        for (size_t tab = from + ts - from % ts; tab <= to; tab += ts) {
            putchar('\t');
            from = tab;
        }
    while (from++ < to) putchar(' ');
    return to;
}

static size_t diffHalfLine(const Diff *d, const char *line, size_t len, size_t indent, size_t bound) {
    size_t in = 0, out = 0, ts = (size_t)d->tabSize;
    for (size_t k = 0; k < len; k++) {
        unsigned char c = (unsigned char)line[k];
        if (c == '\t') {
            size_t spaces = ts - in % ts;
            if (in == out) {
                size_t stop = out + spaces;
                if (d->expandTabs) {
                    if (bound < stop) stop = bound;
                    for (; out < stop; out++) putchar(' ');
                } else if (stop < bound) {
                    out = stop;
                    putchar('\t');
                }
            }
            in += spaces;
        } else if (c == '\r') {
            putchar('\r');
            diffTabTo(d, 0, indent);
            in = out = 0;
        } else if (c == '\b') {
            if (in != 0 && --in < bound) {
                if (out <= in) for (; out < in; out++) putchar(' ');
                else { out = in; putchar('\b'); }
            }
        } else if (c < 0x20 || c == 0x7f) {
            /* zero width */
            if (in < bound) putchar((char)c);
        } else if ((c & 0xc0) == 0x80) {
            /* UTF-8 continuation: no column of its own */
            if (in <= bound && out == in) putchar((char)c);
        } else {
            if (in++ < bound) {
                out = in;
                putchar((char)c);
            }
        }
    }
    return out;
}

static void diffSideLine(const Diff *d, const DiffFile *a, lin i, char sep, const DiffFile *b, lin j, size_t hw,
                         size_t c2o) {
    size_t col = 0;
    bool nl = false;
    if (a) {
        nl |= !(i == a->nlines - 1 && a->missingNewline);
        col = diffHalfLine(d, a->line[i], a->len[i], 0, hw);
    }
    if (sep != ' ') {
        col = diffTabTo(d, col, (hw + c2o - 1) / 2) + 1;
        if (sep == '|' && nl != !(j == b->nlines - 1 && b->missingNewline)) sep = nl ? '/' : '\\';
        putchar(sep);
    }
    if (b) {
        nl |= !(j == b->nlines - 1 && b->missingNewline);
        if (b->len[j]) {
            col = diffTabTo(d, col, c2o);
            diffHalfLine(d, b->line[j], b->len[j], col, hw);
        }
    }
    if (nl) putchar('\n');
}

static void diffSide(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    long w = d->width, t = d->expandTabs ? 1 : d->tabSize;
    long off = (w + t + 3) / (2 * t) * t;
    long hwl = off - 3 < w - off ? off - 3 : w - off;
    size_t hw = hwl > 0 ? (size_t)hwl : 0;
    size_t c2o = hw ? (size_t)off : (size_t)w;
    lin i = 0, j = 0;
    for (DiffChange *c = script;; c = c->next) {
        while (c && c->ignore) c = c->next;   /* ignorable hunks print as common lines */
        lin until0 = c ? c->line0 : a->nlines, until1 = c ? c->line1 : b->nlines;
        if (!d->suppressCommon) {
            for (; i < until0 && j < until1; i++, j++) {
                if (d->leftColumn) diffSideLine(d, a, i, '(', NULL, 0, hw, c2o);
                else diffSideLine(d, a, i, ' ', b, j, hw, c2o);
            }
            for (; j < until1; j++) diffSideLine(d, NULL, 0, '>', b, j, hw, c2o);
            for (; i < until0; i++) diffSideLine(d, a, i, '<', NULL, 0, hw, c2o);
        }
        i = until0;
        j = until1;
        if (!c) break;
        lin n = c->deleted > c->inserted ? c->deleted : c->inserted;
        for (lin k = 0; k < n; k++) {
            if (k < c->deleted && k < c->inserted) diffSideLine(d, a, i + k, '|', b, j + k, hw, c2o);
            else if (k < c->deleted) diffSideLine(d, a, i + k, '<', NULL, 0, hw, c2o);
            else diffSideLine(d, NULL, 0, '>', b, j + k, hw, c2o);
        }
        i += c->deleted;
        j += c->inserted;
    }
}

/* GNU's context headers keep the traditional date in the C/POSIX locale
 * (hard_locale(LC_TIME) is false); unified headers always use ISO. */
static bool diffHardLocale(void) {
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_TIME");
    if (!v || !*v) v = getenv("LANG");
    return v && *v && strcmp(v, "C") && strcmp(v, "POSIX");
}

static void diffStamp(const Diff *d, const DiffFile *f, char *out, size_t n) {
    struct timespec ts = DIFF_MTIM(&f->st);
    time_t t = ts.tv_sec;
    struct tm tm;
    char a[64], z[16];
    localtime_r(&t, &tm);
    if (d->format == OUT_CONTEXT && !diffHardLocale()) {
        strftime(out, n, "%a %b %e %T %Y", &tm);
        return;
    }
    strftime(a, sizeof(a), "%Y-%m-%d %H:%M:%S", &tm);
    strftime(z, sizeof(z), "%z", &tm);
    snprintf(out, n, "%s.%09ld %s", a, (long)ts.tv_nsec, z);
}

static void diffHeader(const Diff *d, const DiffFile *a, const DiffFile *b) {
    const char *m0 = d->format == OUT_CONTEXT ? "***" : "---";
    const char *m1 = d->format == OUT_CONTEXT ? "---" : "+++";
    char s0[96], s1[96];
    if (d->label[0]) printf("%s %s\n", m0, d->label[0]);
    else { diffStamp(d, a, s0, sizeof(s0)); printf("%s %s\t%s\n", m0, a->name, s0); }
    if (d->label[1]) printf("%s %s\n", m1, d->label[1]);
    else { diffStamp(d, b, s1, sizeof(s1)); printf("%s %s\t%s\n", m1, b->name, s1); }
}

/* -p/-F: GNU's find_function -- the last heading line before the hunk's
 * first line, searching back no further than the previous search began
 * (and reusing what that one found). */
static void diffFunction(const Diff *d, const DiffFile *a, lin first, lin *lastSearch, lin *lastMatch) {
    if (!d->showFunction && !d->haveFuncRe) return;
    lin found = -1;
    for (lin i = first - 1; i >= *lastSearch; i--) {
        const char *s = a->line[i];
        size_t n = a->len[i];
        bool match;
        if (d->haveFuncRe) {
            regmatch_t m[1];
            m[0].rm_so = 0;
            m[0].rm_eo = (regoff_t)n;
            match = regexec(&d->funcRe, s, 1, m, REG_STARTEND) == 0;
        } else {
            match = n > 0 && (isalpha((unsigned char)s[0]) || s[0] == '_' || s[0] == '$');
        }
        if (match) { found = i; break; }
    }
    *lastSearch = first;
    if (found >= 0) *lastMatch = found;
    else found = *lastMatch;
    if (found < 0) return;
    const char *l = a->line[found];
    size_t n = a->len[found], i = 0;
    while (i < n && isspace((unsigned char)l[i])) i++;
    size_t j = i;
    while (j < i + 40 && j < n) j++;
    while (j > i && isspace((unsigned char)l[j - 1])) j--;
    putchar(' ');
    fwrite(l + i, 1, j - i, stdout);
}

/* Groups changes into hunks as GNU's find_hunk: a following change joins
 * when fewer than 2*context+1 lines (context, if it is ignorable) part
 * them. Returns the last change of the hunk starting at `start`. */
static DiffChange *diffHunkEnd(const Diff *d, DiffChange *start) {
    DiffChange *prev;
    for (;;) {
        lin top0 = start->line0 + start->deleted;
        prev = start;
        start = start->next;
        lin thresh = start && start->ignore ? d->context : 2 * d->context + 1;
        if (!start || start->line0 - top0 >= thresh) break;
    }
    return prev;
}

static void diffUnifiedRange(lin a, lin b) {
    lin ta = a + 1, tb = b + 1;
    if (tb <= ta) printf(tb < ta ? "%ld,0" : "%ld", tb);
    else printf("%ld,%ld", ta, tb - ta + 1);
}

static void diffContextRange(lin a, lin b) {
    lin ta = a + 1, tb = b + 1;
    if (tb <= ta) printf("%ld", tb);
    else printf("%ld,%ld", ta, tb);
}

static void diffHunks(const Diff *d, DiffChange *script, const DiffFile *a, const DiffFile *b) {
    bool header = false;
    lin fsearch = 0, fmatch = -1;
    for (DiffChange *c = script; c;) {
        DiffChange *last = diffHunkEnd(d, c);
        DiffChange *after = last->next;
        bool any = false, show0 = false, show1 = false;
        for (DiffChange *k = c; k != after; k = k->next) {
            if (k->ignore) continue;
            any = true;
            if (k->deleted) show0 = true;
            if (k->inserted) show1 = true;
        }
        if (!any) { c = after; continue; }
        if (!header) { diffHeader(d, a, b); header = true; }
        lin first0 = c->line0 - d->context, first1 = c->line1 - d->context;
        if (first0 < 0) first0 = 0;
        if (first1 < 0) first1 = 0;
        lin last0 = last->line0 + last->deleted - 1 + d->context;
        lin last1 = last->line1 + last->inserted - 1 + d->context;
        if (last0 > a->nlines - 1) last0 = a->nlines - 1;
        if (last1 > b->nlines - 1) last1 = b->nlines - 1;
        if (d->format == OUT_UNIFIED) {
            fputs("@@ -", stdout);
            diffUnifiedRange(first0, last0);
            fputs(" +", stdout);
            diffUnifiedRange(first1, last1);
            fputs(" @@", stdout);
            diffFunction(d, a, first0, &fsearch, &fmatch);
            putchar('\n');
            lin i = first0, j = first1;
            for (DiffChange *k = c; k != after; k = k->next) {
                for (; i < k->line0; i++, j++) diffLine(d, " ", a, i);
                for (lin x = 0; x < k->deleted; x++) diffLine(d, "-", a, i++);
                for (lin x = 0; x < k->inserted; x++) diffLine(d, "+", b, j++);
            }
            for (; i <= last0; i++) diffLine(d, " ", a, i);
        } else {
            fputs("***************", stdout);
            diffFunction(d, a, first0, &fsearch, &fmatch);
            fputs("\n*** ", stdout);
            diffContextRange(first0, last0);
            fputs(" ****\n", stdout);
            if (show0) {
                lin i = first0;
                for (DiffChange *k = c; k != after; k = k->next) {
                    for (; i < k->line0; i++) diffLine(d, " ", a, i);
                    for (lin x = 0; x < k->deleted; x++, i++)
                        diffLine(d, k->ignore ? " " : k->inserted ? "!" : "-", a, i);
                }
                for (; i <= last0; i++) diffLine(d, " ", a, i);
            }
            fputs("--- ", stdout);
            diffContextRange(first1, last1);
            fputs(" ----\n", stdout);
            if (show1) {
                lin j = first1;
                for (DiffChange *k = c; k != after; k = k->next) {
                    for (; j < k->line1; j++) diffLine(d, " ", b, j);
                    for (lin x = 0; x < k->inserted; x++, j++)
                        diffLine(d, k->ignore ? " " : k->deleted ? "!" : "+", b, j);
                }
                for (; j <= last1; j++) diffLine(d, " ", b, j);
            }
        }
        c = after;
    }
}

/* --- Comparing two files. --- */

static void diffTrouble(Diff *d, const char *name) {
    fprintf(stderr, "diff: %s: %s\n", name, strerror(errno));
    d->status = 2;
}

/* 0 same, 1 differ, 2 trouble. `header` is the "diff -r a/f b/f" line. */
static int diffFiles(Diff *d, const char *p0, const char *p1, const char *header, bool absent0, bool absent1) {
    DiffFile a, b;
    bool ok0 = absent0 ? (memset(&a, 0, sizeof(a)), a.name = p0, true) : diffRead(d, p0, &a);
    if (!ok0) { diffTrouble(d, p0); return 2; }
    bool ok1 = absent1 ? (memset(&b, 0, sizeof(b)), b.name = p1, true) : diffRead(d, p1, &b);
    if (!ok1) { diffTrouble(d, p1); diffFreeFile(&a); return 2; }
    if (absent0) a.st = b.st, DIFF_MTIM(&a.st).tv_sec = 0, DIFF_MTIM(&a.st).tv_nsec = 0;
    if (absent1) b.st = a.st, DIFF_MTIM(&b.st).tv_sec = 0, DIFF_MTIM(&b.st).tv_nsec = 0;
    int result = 0;
    bool same = a.size == b.size && (a.size == 0 || !memcmp(a.data, b.data, a.size));
    if (!same && (a.binary || b.binary)) {
        if (header) puts(header);
        printf("Binary files %s and %s differ\n", p0, p1);
        result = 1;
    } else if (!same) {
        DiffClasses cls = {NULL, 0, 0, 0};
        DiffChange *script = diffScript(d, &a, &b, &cls);
        diffMarkIgnorable(d, script, &a, &b);
        bool shown = false;
        for (DiffChange *c = script; c; c = c->next)
            if (!c->ignore) shown = true;
        if (shown) {
            result = 1;
            if (d->brief) {
                printf("Files %s and %s differ\n", p0, p1);
            } else {
                if (header) puts(header);
                switch (d->format) {
                case OUT_CONTEXT: case OUT_UNIFIED: diffHunks(d, script, &a, &b); break;
                case OUT_ED: diffEd(d, script, &a, &b); break;
                case OUT_RCS: diffRcs(d, script, &a, &b); break;
                case OUT_SIDE: diffSide(d, script, &a, &b); break;
                default: diffNormal(d, script, &a, &b); break;
                }
            }
        }
        diffFreeScript(script);
        for (size_t i = 0; i < cls.cap; i++) free(cls.v[i].key);
        free(cls.v);
    }
    if (result == 0 && d->format == OUT_SIDE && !d->brief && !d->suppressCommon && !(a.binary || b.binary)) {
        if (header) puts(header);
        diffSide(d, NULL, &a, &b);
    }
    if (result == 0 && d->reportSame) printf("Files %s and %s are identical\n", p0, p1);
    if (d->format == OUT_ED) {
        /* an ed script cannot say "no newline": GNU warns after the script */
        fflush(stdout);
        for (int k = 0; k < 2; k++) {
            DiffFile *f = k ? &b : &a;
            if (f->missingNewline && !(k ? absent1 : absent0)) {
                fprintf(stderr, "diff: %s: No newline at end of file\n\n", f->name);
                d->status = 2;
            }
        }
    }
    diffFreeFile(&a);
    diffFreeFile(&b);
    if (result > d->status) d->status = result;
    return result;
}

static bool diffExcluded(const Diff *d, const char *name) {
    for (size_t i = 0; i < d->nexclude; i++)
        if (fnmatch(d->exclude[i], name, 0) == 0) return true;
    return false;
}

static int diffNameCmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char **diffList(const char *dir, size_t *n) {
    *n = 0;
    struct stat st;
    if (stat(dir, &st) != 0 && errno == ENOENT) return (char **)calloc(1, sizeof(char *));   /* -N: empty */
    DIR *dd = opendir(dir);
    if (!dd) return NULL;
    size_t cap = 32;
    char **v = (char **)malloc(cap * sizeof(char *));
    struct dirent *e;
    while (v && (e = readdir(dd))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (*n == cap) {
            char **g = (char **)realloc(v, (cap *= 2) * sizeof(char *));
            if (!g) break;
            v = g;
        }
        v[(*n)++] = strdup(e->d_name);
    }
    closedir(dd);
    if (v) qsort(v, *n, sizeof(char *), diffNameCmp);
    return v;
}

static char *diffJoin(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *p = (char *)malloc(la + lb + 2);
    if (!p) return NULL;
    memcpy(p, a, la);
    if (la && a[la - 1] != '/') p[la++] = '/';
    memcpy(p + la, b, lb + 1);
    return p;
}

static void diffDirs(Diff *d, const char *d0, const char *d1);

static void diffPair(Diff *d, const char *p0, const char *p1, bool top) {
    struct stat s0, s1;
    bool e0 = stat(p0, &s0) == 0, e1 = stat(p1, &s1) == 0;
    /* -N makes a missing file empty, operands included; not both. */
    if ((!e0 && (!d->newFile || !e1)) && !(d->unidirectionalNew && e1)) { diffTrouble(d, p0); return; }
    if (!e1 && !d->newFile) { diffTrouble(d, p1); return; }
    (void)top;
    bool dir0 = e0 && S_ISDIR(s0.st_mode), dir1 = e1 && S_ISDIR(s1.st_mode);
    if (dir0 && dir1) {
        diffDirs(d, p0, p1);
        return;
    }
    if (dir0 != dir1 && e0 && e1) {
        printf("File %s is a %s while file %s is a %s\n", p0, dir0 ? "directory" : "regular file", p1,
               dir1 ? "directory" : "regular file");
        if (d->status < 1) d->status = 1;
        return;
    }
    char *header = NULL;
    if (!top && !d->brief) {
        size_t n = strlen(d->switches) + strlen(p0) + strlen(p1) + 16;
        header = (char *)malloc(n);
        if (header) snprintf(header, n, "diff%s%s %s %s", *d->switches ? " " : "", d->switches, p0, p1);
    }
    diffFiles(d, p0, p1, header, !e0, !e1);
    free(header);
}

static void diffDirs(Diff *d, const char *d0, const char *d1) {
    size_t n0, n1;
    char **l0 = diffList(d0, &n0), **l1 = diffList(d1, &n1);
    if (!l0) { diffTrouble(d, d0); }
    if (!l1) { diffTrouble(d, d1); }
    size_t i = 0, j = 0;
    while (l0 && l1 && (i < n0 || j < n1)) {
        int cmp = i == n0 ? 1 : j == n1 ? -1 : strcmp(l0[i], l1[j]);
        const char *name = cmp <= 0 ? l0[i] : l1[j];
        if (diffExcluded(d, name)) {
            if (cmp <= 0) i++;
            if (cmp >= 0) j++;
            continue;
        }
        char *p0 = diffJoin(d0, name), *p1 = diffJoin(d1, name);
        if (cmp == 0) {
            struct stat s0, s1;
            bool dir0 = stat(p0, &s0) == 0 && S_ISDIR(s0.st_mode);
            bool dir1 = stat(p1, &s1) == 0 && S_ISDIR(s1.st_mode);
            if (dir0 && dir1 && !d->recursive) {
                printf("Common subdirectories: %s and %s\n", p0, p1);
            } else {
                diffPair(d, p0, p1, false);
            }
            i++;
            j++;
        } else {
            bool in0 = cmp < 0;
            struct stat s;
            bool isDir = stat(in0 ? p0 : p1, &s) == 0 && S_ISDIR(s.st_mode);
            if (d->newFile && isDir && d->recursive) {
                diffDirs(d, p0, p1);
            } else if ((d->newFile || (d->unidirectionalNew && !in0)) && !isDir) {
                diffPair(d, p0, p1, false);
            } else {
                printf("Only in %s: %s\n", in0 ? d0 : d1, name);
                if (d->status < 1) d->status = 1;
            }
            if (in0) i++;
            else j++;
        }
        free(p0);
        free(p1);
    }
    for (size_t k = 0; k < n0 && l0; k++) free(l0[k]);
    for (size_t k = 0; k < n1 && l1; k++) free(l1[k]);
    free(l0);
    free(l1);
}

/* --- Options. --- */

static int diffTry(void) {
    fputs("diff: Try 'diff --help' for more information.\n", stderr);
    return 2;
}

static void diffUsage(void) {
    fputs("Usage: diff [OPTION]... FILES\n"
          "Compare FILES line by line.\n\n"
          "      --normal                  output a normal diff (the default)\n"
          "  -q, --brief                   report only when files differ\n"
          "  -s, --report-identical-files  report when two files are the same\n"
          "  -c, -C NUM, --context[=NUM]   output NUM (default 3) lines of copied context\n"
          "  -u, -U NUM, --unified[=NUM]   output NUM (default 3) lines of unified context\n"
          "  -e, --ed                      output an ed script\n"
          "  -n, --rcs                     output an RCS format diff\n"
          "  -p, --show-c-function         show which C function each change is in\n"
          "  -F, --show-function-line=RE   show the most recent line matching RE\n"
          "      --label LABEL             use LABEL instead of file name and timestamp\n"
          "  -t, --expand-tabs             expand tabs to spaces in output\n"
          "  -T, --initial-tab             make tabs line up by prepending a tab\n"
          "      --tabsize=NUM             tab stops every NUM (default 8) print columns\n"
          "  -r, --recursive               recursively compare any subdirectories found\n"
          "  -N, --new-file                treat absent files as empty\n"
          "      --unidirectional-new-file  treat absent first files as empty\n"
          "  -x, --exclude=PAT             exclude files that match PAT\n"
          "  -X, --exclude-from=FILE       exclude files that match any pattern in FILE\n"
          "  -i, --ignore-case             ignore case differences in file contents\n"
          "  -E, --ignore-tab-expansion    ignore changes due to tab expansion\n"
          "  -Z, --ignore-trailing-space   ignore white space at line end\n"
          "  -b, --ignore-space-change     ignore changes in the amount of white space\n"
          "  -w, --ignore-all-space        ignore all white space\n"
          "  -B, --ignore-blank-lines      ignore changes where lines are all blank\n"
          "  -I, --ignore-matching-lines=RE  ignore changes where all lines match RE\n"
          "  -a, --text                    treat all files as text\n"
          "      --strip-trailing-cr       strip trailing carriage return on input\n"
          "  -d, --minimal                 try hard to find a smaller set of changes\n"
          "      --help               display this help and exit\n"
          "  -v, --version            output version information and exit\n\n"
          "Exit status is 0 if inputs are the same, 1 if different, 2 if trouble.\n",
          stdout);
}

typedef struct {
    const char *name;
    int c;
    int arg;          /* 0 none, 1 required, 2 optional */
} DiffLong;

static const DiffLong diffLongs[] = {
    {"normal", 1, 0}, {"brief", 'q', 0}, {"report-identical-files", 's', 0}, {"context", 'C', 2},
    {"unified", 'U', 2}, {"ed", 'e', 0}, {"rcs", 'n', 0}, {"show-c-function", 'p', 0},
    {"show-function-line", 'F', 1}, {"label", 2, 1}, {"expand-tabs", 't', 0}, {"initial-tab", 'T', 0},
    {"tabsize", 3, 1}, {"recursive", 'r', 0}, {"new-file", 'N', 0}, {"unidirectional-new-file", 4, 0},
    {"exclude", 'x', 1}, {"exclude-from", 'X', 1}, {"ignore-case", 'i', 0}, {"ignore-tab-expansion", 'E', 0},
    {"ignore-trailing-space", 'Z', 0}, {"ignore-space-change", 'b', 0}, {"ignore-all-space", 'w', 0},
    {"ignore-blank-lines", 'B', 0}, {"ignore-matching-lines", 'I', 1}, {"text", 'a', 0},
    {"strip-trailing-cr", 5, 0}, {"minimal", 'd', 0}, {"speed-large-files", 6, 0}, {"help", 7, 0},
    {"version", 'v', 0}, {"no-dereference", 8, 0}, {"side-by-side", 'y', 0}, {"width", 'W', 1},
    {"left-column", 9, 0}, {"suppress-common-lines", 10, 0},
};

static bool diffContextArg(const char *opt, const char *val, lin *out) {
    char *end;
    long v = strtol(val, &end, 10);
    if (!*val || *end || v < 0) {
        char q[256];
        fprintf(stderr, "diff: invalid context length %s\n", gnuQuote(val, q, sizeof(q)));
        (void)opt;
        return false;
    }
    *out = v;
    return true;
}

static void diffAddSwitch(Diff *d, const char *raw) {
    /* quoted for the shell where needed, as GNU's "diff -r ..." line has it */
    char q[4096];
    const char *arg = raw;
    if (strpbrk(raw, " \t\n!\"#$&'()*;<=>?[\\]^`{|}~") || !*raw) arg = gnuQuote(raw, q, sizeof(q));
    size_t n = strlen(d->switches), m = strlen(arg);
    char *v = (char *)realloc(d->switches, n + m + 2);
    if (!v) return;
    d->switches = v;
    if (n) d->switches[n++] = ' ';
    memcpy(d->switches + n, arg, m + 1);
}

static void diffStyle(Diff *d, int style) {
    if (d->styleSet >= 0 && d->styleSet != style) d->styleConflict = true;
    d->styleSet = style;
    d->format = style;
}

/* One option; 1 to stop with d->status. */
static int diffOption(Diff *d, int c, const char *val) {
    char q[256];
    switch (c) {
    case 1: diffStyle(d, OUT_NORMAL); break;
    case 'y': diffStyle(d, OUT_SIDE); break;
    case 'W': {
        char *end;
        long v = strtol(val, &end, 10);
        if (!*val || *end || v <= 0) {
            fprintf(stderr, "diff: invalid width %s\n", gnuQuote(val, q, sizeof(q)));
            d->status = diffTry();
            return 1;
        }
        d->width = v;
        break;
    }
    case 9: d->leftColumn = true; break;
    case 10: d->suppressCommon = true; break;
    case 'q': d->brief = true; break;
    case 's': d->reportSame = true; break;
    case 'c': diffStyle(d, OUT_CONTEXT); d->context = 3; break;
    case 'u': diffStyle(d, OUT_UNIFIED); d->context = 3; break;
    case 'C': diffStyle(d, OUT_CONTEXT); if (val && !diffContextArg("C", val, &d->context)) { d->status = diffTry(); return 1; } if (!val) d->context = 3; break;
    case 'U': diffStyle(d, OUT_UNIFIED); if (val && !diffContextArg("U", val, &d->context)) { d->status = diffTry(); return 1; } if (!val) d->context = 3; break;
    case 'e': diffStyle(d, OUT_ED); break;
    case 'n': diffStyle(d, OUT_RCS); break;
    case 'p': d->showFunction = true; break;
    case 'F':
        if (d->haveFuncRe) regfree(&d->funcRe);
        if (regcomp(&d->funcRe, val, gnuRegexFlags(REG_NOSUB)) != 0) {
            fprintf(stderr, "diff: %s\n", "Invalid regular expression");
            d->status = 2;
            return 1;
        }
        d->haveFuncRe = true;
        break;
    case 2:
        if (d->nlabels >= 2) {
            fputs("diff: too many file label options\n", stderr);
            d->status = 2;
            return 1;
        }
        d->label[d->nlabels++] = val;
        break;
    case 't': d->expandTabs = true; break;
    case 'T': d->initialTab = true; break;
    case 3: {
        char *end;
        long v = strtol(val, &end, 10);
        if (!*val || *end || v <= 0) {
            fprintf(stderr, "diff: invalid tabsize %s\n", gnuQuoteLocale(val, q, sizeof(q)));
            d->status = 2;
            return 1;
        }
        d->tabSize = (int)v;
        break;
    }
    case 'r': d->recursive = true; break;
    case 'N': d->newFile = true; break;
    case 4: d->unidirectionalNew = true; break;
    case 'x': {
        char **v = (char **)realloc(d->exclude, (d->nexclude + 1) * sizeof(char *));
        if (v) { d->exclude = v; d->exclude[d->nexclude++] = (char *)val; }
        break;
    }
    case 'X': {
        FILE *fp = smallclueAppOpenRead(val);
        if (!fp) {
            fprintf(stderr, "diff: %s: %s\n", val, strerror(errno));
            d->status = 2;
            return 1;
        }
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            if (!*line) continue;
            char **v = (char **)realloc(d->exclude, (d->nexclude + 1) * sizeof(char *));
            if (v) { d->exclude = v; d->exclude[d->nexclude++] = strdup(line); }
        }
        fclose(fp);
        break;
    }
    case 'i': d->ignoreCase = true; break;
    case 'E': d->ignoreTabExpansion = true; break;
    case 'Z': d->ignoreTrailingSpace = true; break;
    case 'b': d->ignoreSpaceChange = true; break;
    case 'w': d->ignoreAllSpace = true; break;
    case 'B': d->ignoreBlank = true; break;
    case 'I': {
        regex_t *v = (regex_t *)realloc(d->ignoreRe, (d->nIgnoreRe + 1) * sizeof(regex_t));
        if (!v) break;
        d->ignoreRe = v;
        int r = regcomp(&d->ignoreRe[d->nIgnoreRe], val, gnuRegexFlags(REG_NOSUB));
        if (r != 0) {
            fprintf(stderr, "diff: %s\n", gnuRegexMessage(r));
            d->status = 2;
            return 1;
        }
        d->nIgnoreRe++;
        break;
    }
    case 'a': d->text = true; break;
    case 5: d->stripCr = true; break;
    case 'd': d->minimal = true; break;
    case 6: case 8: break;
    case 7: diffUsage(); d->status = 0; return 1;
    case 'v': puts("diff (SmallCLUE) 3.10"); d->status = 0; return 1;
    default: break;
    }
    return 0;
}

int smallclueDiffCommand(int argc, char **argv) {
    Diff *d = (Diff *)calloc(1, sizeof(Diff));
    char **ops = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nops = 0, status = 2;
    if (!d || !ops) { free(d); free(ops); return 2; }
    d->format = OUT_NORMAL;
    d->styleSet = -1;
    d->width = 130;
    d->context = 3;
    d->tabSize = 8;
    d->switches = strdup("");
    bool endOfOptions = false;
    char q[4096];
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            ops[nops++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        int startI = i;
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            const DiffLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(diffLongs) / sizeof(diffLongs[0]); k++) {
                if (strncmp(diffLongs[k].name, opt, len)) continue;
                if (strlen(diffLongs[k].name) == len) { m = &diffLongs[k]; matches = 1; break; }
                m = &diffLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "diff: option '%s' is ambiguous\n" : "diff: unrecognized option '%s'\n", arg);
                status = diffTry();
                goto done;
            }
            const char *val = NULL;
            if (eq) {
                if (!m->arg) {
                    fprintf(stderr, "diff: option '--%s' doesn't allow an argument\n", m->name);
                    status = diffTry();
                    goto done;
                }
                val = eq + 1;
            } else if (m->arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "diff: option '--%s' requires an argument\n", m->name);
                    status = diffTry();
                    goto done;
                }
                val = argv[++i];
            }
            if (diffOption(d, m->c, val)) { status = d->status; goto done; }
        } else {
            for (const char *p = arg + 1; *p; p++) {
                char c = *p;
                if (isdigit((unsigned char)c)) {
                    /* -NUM: obsolete context count */
                    long v = 0;
                    while (isdigit((unsigned char)*p)) v = v * 10 + (*p++ - '0');
                    p--;
                    d->context = v;
                    continue;
                }
                if (strchr("CUFIxXLW", c)) {
                    const char *val = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
                    if (!val) {
                        fprintf(stderr, "diff: option requires an argument -- '%c'\n", c);
                        status = diffTry();
                        goto done;
                    }
                    if (diffOption(d, c == 'L' ? 2 : c, val)) { status = d->status; goto done; }
                    break;
                }
                if (!strchr("qscuenptTrNiEZbwBadvy", c)) {
                    fprintf(stderr, "diff: invalid option -- '%c'\n", c);
                    status = diffTry();
                    goto done;
                }
                if (diffOption(d, c, NULL)) { status = d->status; goto done; }
            }
        }
        /* the options as typed, for "diff -r -u a/f b/f" */
        for (int k = startI; k <= i; k++) diffAddSwitch(d, argv[k]);
    }
    if (d->styleConflict) {
        fputs("diff: conflicting output style options\n", stderr);
        status = diffTry();
        goto done;
    }
    if (nops < 2) {
        if (nops == 0) fputs("diff: missing operand after 'diff'\n", stderr);
        else fprintf(stderr, "diff: missing operand after %s\n", gnuQuote(ops[0], q, sizeof(q)));
        status = diffTry();
        goto done;
    }
    if (nops > 2) {
        fprintf(stderr, "diff: extra operand %s\n", gnuQuote(ops[2], q, sizeof(q)));
        status = diffTry();
        goto done;
    }
    {
        /* A directory and a file: the file of the same name in the directory. */
        const char *p0 = ops[0], *p1 = ops[1];
        char *alloc = NULL;
        struct stat s0, s1;
        bool dir0 = strcmp(p0, "-") && stat(p0, &s0) == 0 && S_ISDIR(s0.st_mode);
        bool dir1 = strcmp(p1, "-") && stat(p1, &s1) == 0 && S_ISDIR(s1.st_mode);
        if (dir0 && !dir1 && strcmp(p1, "-")) {
            const char *base = strrchr(p1, '/');
            alloc = diffJoin(p0, base ? base + 1 : p1);
            p0 = alloc;
        } else if (dir1 && !dir0 && strcmp(p0, "-")) {
            const char *base = strrchr(p0, '/');
            alloc = diffJoin(p1, base ? base + 1 : p0);
            p1 = alloc;
        }
        if (!strcmp(p0, "-") || !strcmp(p1, "-")) diffFiles(d, p0, p1, NULL, false, false);
        else diffPair(d, p0, p1, true);
        free(alloc);
    }
    status = d->status;

done:
    fflush(stdout);
    if (ferror(stdout)) status = 2;
    for (size_t k = 0; k < d->nIgnoreRe; k++) regfree(&d->ignoreRe[k]);
    free(d->ignoreRe);
    if (d->haveFuncRe) regfree(&d->funcRe);
    free(d->exclude);
    free(d->switches);
    free(d);
    free(ops);
    return status;
}
