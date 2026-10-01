/*
 * du: GNU coreutils 9 compatible. -a -s -d -c -S -l -x -L -D/-H -P, -b and
 * --apparent-size (directories counting 0, as du 9 does), --inodes, -k -m
 * -B (N, suffix-only like K/KB/KiB/M, human-readable, si) and the
 * DU_BLOCK_SIZE / BLOCK_SIZE / BLOCKSIZE / POSIXLY_CORRECT defaults, -h and
 * --si with GNU's rounding up, -t, --exclude/-X, --time[=WORD] with
 * --time-style, -0, --files0-from; a file reached twice (a hard link, or
 * an operand repeated when there are several) counted once; readdir order.
 */

#include "du_app.h"

#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#if defined(__APPLE__) && !defined(st_mtim)
#define DU_TIME(st, w) ((w) == 'a' ? (st)->st_atimespec : (w) == 'c' ? (st)->st_ctimespec : (st)->st_mtimespec)
#else
#define DU_TIME(st, w) ((w) == 'a' ? (st)->st_atim : (w) == 'c' ? (st)->st_ctim : (st)->st_mtim)
#endif

typedef struct {
    dev_t dev;
    ino_t ino;
} DuId;

typedef struct {
    bool all, apparent, inodes, countLinks, oneFs, separate, total, deref, derefArgs, human, si;
    intmax_t maxDepth;
    uintmax_t blockSize;
    char unitSuffix[8];     /* -BK and friends: printed after the number */
    bool threshSet;
    intmax_t threshold;
    char timeWhich;         /* 0, 'm', 'a', 'c' */
    const char *timeFmt;
    char delim;
    char **excludes;
    size_t nexcludes;
    bool hashAll;
    DuId *seen;
    size_t nseen, capSeen;
    dev_t rootDev;
    int status;
} Du;

typedef struct {
    uintmax_t size;
    struct timespec tmax;
} DuSum;

/* (dev, ino) already counted? An open-addressing set; ino 0 marks a free
 * slot, so a real inode 0 is stored as ~0. */
static bool duSeen(Du *d, const struct stat *st) {
    ino_t ino = st->st_ino ? st->st_ino : (ino_t)~(ino_t)0;
    if (d->nseen * 2 >= d->capSeen) {
        size_t cap = d->capSeen ? d->capSeen * 2 : 1024;
        DuId *t = (DuId *)calloc(cap, sizeof(DuId));
        if (!t) return false;
        for (size_t i = 0; i < d->capSeen; i++) {
            if (!d->seen[i].ino) continue;
            size_t h = (size_t)(d->seen[i].ino * 2654435761u ^ (uintmax_t)d->seen[i].dev) & (cap - 1);
            while (t[h].ino) h = (h + 1) & (cap - 1);
            t[h] = d->seen[i];
        }
        free(d->seen);
        d->seen = t;
        d->capSeen = cap;
    }
    size_t h = (size_t)(ino * 2654435761u ^ (uintmax_t)st->st_dev) & (d->capSeen - 1);
    while (d->seen[h].ino) {
        if (d->seen[h].ino == ino && d->seen[h].dev == st->st_dev) return true;
        h = (h + 1) & (d->capSeen - 1);
    }
    d->seen[h].dev = st->st_dev;
    d->seen[h].ino = ino;
    d->nseen++;
    return false;
}

static bool duExcluded(const Du *d, const char *path) {
    for (size_t i = 0; i < d->nexcludes; i++) {
        const char *p = path;
        for (;;) {
            if (fnmatch(d->excludes[i], p, 0) == 0) return true;
            const char *slash = strchr(p, '/');
            if (!slash) break;
            p = slash + 1;
        }
    }
    return false;
}

/* human_readable with human_ceiling and autoscale. */
static void duHuman(char *out, size_t n, uintmax_t bytes, unsigned base) {
    static const char units[] = "KMGTPEZYRQ";
    if (bytes < base) {
        snprintf(out, n, "%ju", bytes);
        return;
    }
    int exp = 0;
    long double v = (long double)bytes;
    while (v >= base && exp < 10) {
        v /= base;
        exp++;
    }
    char unit = base == 1000 && exp == 1 ? 'k' : units[exp - 1];
    if (v < 10) {
        long double tenths = ceill(v * 10 - 1e-9L);
        if (tenths >= 100) snprintf(out, n, "%.0Lf%c", tenths / 10, unit);
        else snprintf(out, n, "%.1Lf%c", tenths / 10, unit);
    } else {
        long double whole = ceill(v - 1e-9L);
        if (whole >= base && exp < 10) snprintf(out, n, "1.0%c", base == 1000 ? units[exp] : units[exp]);
        else snprintf(out, n, "%.0Lf%c", whole, unit);
    }
}

static void duPrint(Du *d, const DuSum *s, const char *name) {
    if (d->threshSet) {
        if (d->threshold >= 0 ? (intmax_t)s->size < d->threshold : (intmax_t)s->size > -d->threshold) return;
    }
    char num[64];
    if (d->inodes) snprintf(num, sizeof(num), "%ju", s->size);
    else if (d->human || d->si) duHuman(num, sizeof(num), s->size, d->si ? 1000 : 1024);
    else snprintf(num, sizeof(num), "%ju%s", (s->size + d->blockSize - 1) / d->blockSize, d->unitSuffix);
    fputs(num, stdout);
    putchar('\t');
    if (d->timeWhich) {
        char tb[128];
        struct tm tm;
        time_t t = s->tmax.tv_sec;
        localtime_r(&t, &tm);
        if (!strcmp(d->timeFmt, "full-iso")) {
            char a[64], z[16];
            strftime(a, sizeof(a), "%Y-%m-%d %H:%M:%S", &tm);
            strftime(z, sizeof(z), "%z", &tm);
            snprintf(tb, sizeof(tb), "%s.%09ld %s", a, (long)s->tmax.tv_nsec, z);
        } else {
            const char *f = !strcmp(d->timeFmt, "iso") ? "%Y-%m-%d"
                          : d->timeFmt[0] == '+' ? d->timeFmt + 1 : "%Y-%m-%d %H:%M";
            strftime(tb, sizeof(tb), f, &tm);
        }
        fputs(tb, stdout);
        putchar('\t');
    }
    fputs(name, stdout);
    putchar(d->delim);
}

static void duTimeMax(struct timespec *a, struct timespec b) {
    if (b.tv_sec > a->tv_sec || (b.tv_sec == a->tv_sec && b.tv_nsec > a->tv_nsec)) *a = b;
}

/* One entry, recursively; false when it was not counted at all. */
static bool duVisit(Du *d, const char *path, intmax_t level, DuSum *out) {
    char q[4096];
    struct stat st;
    bool follow = d->deref || (level == 0 && d->derefArgs);
    if ((follow ? stat(path, &st) : lstat(path, &st)) != 0) {
        fprintf(stderr, "du: cannot access %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(errno));
        d->status = 1;
        return false;
    }
    if (duExcluded(d, path)) return false;
    if (level == 0) d->rootDev = st.st_dev;
    else if (d->oneFs && st.st_dev != d->rootDev) return false;
    bool isDir = S_ISDIR(st.st_mode);
    if (!d->countLinks && (d->hashAll || (!isDir && st.st_nlink > 1)) && duSeen(d, &st)) return false;
    DuSum self = {0, DU_TIME(&st, d->timeWhich ? d->timeWhich : 'm')};
    self.size = d->inodes ? 1 : d->apparent ? (isDir ? 0 : (uintmax_t)st.st_size) : (uintmax_t)st.st_blocks * 512;
    DuSum total = self;
    if (isDir) {
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "du: cannot read directory %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(errno));
            d->status = 1;
        } else {
            struct dirent *e;
            size_t plen = strlen(path);
            while ((e = readdir(dir))) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                size_t nl = strlen(e->d_name);
                char *child = (char *)malloc(plen + nl + 2);
                memcpy(child, path, plen);
                size_t o = plen;
                if (plen && path[plen - 1] != '/') child[o++] = '/';
                memcpy(child + o, e->d_name, nl + 1);
                DuSum sub;
                struct stat cst;
                bool childDir = lstat(child, &cst) == 0 && S_ISDIR(cst.st_mode);
                if (duVisit(d, child, level + 1, &sub)) {
                    if (!(d->separate && childDir)) total.size += sub.size;
                    duTimeMax(&total.tmax, sub.tmax);
                }
                free(child);
            }
            closedir(dir);
        }
    }
    if ((isDir && level <= d->maxDepth) || (d->all && level <= d->maxDepth) || level == 0) duPrint(d, &total, path);
    *out = total;
    return true;
}

/* --block-size / BLOCK_SIZE: false when invalid. */
static bool duBlockSize(Du *d, const char *spec) {
    if (!strcmp(spec, "human-readable")) {
        d->human = true;
        return true;
    }
    if (!strcmp(spec, "si")) {
        d->si = true;
        return true;
    }
    const char *p = spec;
    if (*p == '\'') p++;
    char *end;
    uintmax_t n = 1;
    bool haveNum = isdigit((unsigned char)*p);
    if (haveNum) {
        errno = 0;
        n = strtoumax(p, &end, 10);
        if (errno) return false;
        p = end;
    }
    uintmax_t mult = 1;
    d->unitSuffix[0] = '\0';
    if (*p) {
        static const char pw[] = "KMGTPEZYRQ";
        char up = *p == 'k' ? 'K' : *p;
        const char *pos = strchr(pw, up);
        unsigned base = 1024;
        const char *rest = p + 1;
        if (!pos) {
            if (*p == 'b' && !p[1]) mult = 512;
            else return false;
        } else {
            if (!strcmp(rest, "B")) base = 1000;
            else if (*rest && strcmp(rest, "iB")) return false;
            for (int i = 0; i <= pos - pw; i++) mult *= base;
            if (!haveNum) {
                if (base == 1000) snprintf(d->unitSuffix, sizeof(d->unitSuffix), "%cB", up == 'K' ? 'k' : up);
                else snprintf(d->unitSuffix, sizeof(d->unitSuffix), "%c%s", up, *rest ? "iB" : "");
            }
        }
    }
    if (!n || !mult) return false;
    d->blockSize = n * mult;
    d->human = d->si = false;
    return true;
}

static const GnuLongOpt duLongs[] = {
    {"all", GNU_NO_ARG, 'a'},           {"apparent-size", GNU_NO_ARG, 1},  {"block-size", GNU_REQ_ARG, 10},
    {"bytes", GNU_NO_ARG, 'b'},         {"count-links", GNU_NO_ARG, 'l'},  {"dereference", GNU_NO_ARG, 'L'},
    {"dereference-args", GNU_NO_ARG, 'D'}, {"exclude", GNU_REQ_ARG, 2},   {"exclude-from", GNU_REQ_ARG, 'X'},
    {"files0-from", GNU_REQ_ARG, 3},    {"human-readable", GNU_NO_ARG, 'h'}, {"inodes", GNU_NO_ARG, 4},
    {"max-depth", GNU_REQ_ARG, 'd'},    {"null", GNU_NO_ARG, '0'},         {"no-dereference", GNU_NO_ARG, 'P'},
    {"one-file-system", GNU_NO_ARG, 'x'}, {"separate-dirs", GNU_NO_ARG, 'S'}, {"si", GNU_NO_ARG, 5},
    {"summarize", GNU_NO_ARG, 's'},     {"threshold", GNU_REQ_ARG, 't'},   {"time", GNU_OPT_ARG, 6},
    {"time-style", GNU_REQ_ARG, 7},     {"total", GNU_NO_ARG, 'c'},        {"help", GNU_NO_ARG, 8},
    {"version", GNU_NO_ARG, 9},
};

int smallclueDuCommand(int argc, char **argv) {
    Du d;
    memset(&d, 0, sizeof(d));
    d.maxDepth = INTMAX_MAX;
    d.delim = '\n';
    d.timeFmt = "long-iso";
    d.blockSize = 1024;
    const char *env = getenv("DU_BLOCK_SIZE");
    if (!env || !*env) env = getenv("BLOCK_SIZE");
    if (!env || !*env) env = getenv("BLOCKSIZE");
    if (env && *env) {
        if (!duBlockSize(&d, env)) d.blockSize = 1024;
    } else if (getenv("POSIXLY_CORRECT")) {
        d.blockSize = 512;
    }
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "du", "0abd:chHklmsxB:DLPSX:t:", duLongs, sizeof(duLongs) / sizeof(duLongs[0]));
    int c, status = 1;
    char q[4096];
    const char *files0 = NULL;
    bool summarize = false, depthSet = false;
    char **names = NULL;
    size_t nnames = 0;
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case '0': d.delim = '\0'; break;
        case 'a': d.all = true; break;
        case 'b': d.apparent = true; d.blockSize = 1; d.unitSuffix[0] = '\0'; d.human = d.si = false; break;
        case 1: d.apparent = true; break;
        case 'c': d.total = true; break;
        case 'd': {
            char *end;
            errno = 0;
            intmax_t v = strtoimax(g.arg, &end, 10);
            if (end == g.arg || *end || v < 0 || errno) {
                fprintf(stderr, "du: invalid maximum depth %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto try;
            }
            d.maxDepth = v;
            depthSet = true;
            break;
        }
        case 'h': d.human = true; d.si = false; break;
        case 5: d.si = true; d.human = false; break;
        case 'k': d.blockSize = 1024; d.unitSuffix[0] = '\0'; d.human = d.si = false; break;
        case 'm': d.blockSize = 1048576; d.unitSuffix[0] = '\0'; d.human = d.si = false; break;
        case 'B': case 10:
            if (!duBlockSize(&d, g.arg)) {
                fprintf(stderr, "du: invalid %s argument %s\n", c == 'B' ? "-B" : "--block-size", gnuQuote(g.arg, q, sizeof(q)));
                goto done;
            }
            break;
        case 'l': d.countLinks = true; break;
        case 's': summarize = true; break;
        case 'x': d.oneFs = true; break;
        case 'D': case 'H': d.derefArgs = true; break;
        case 'L': d.deref = true; break;
        case 'P': d.deref = d.derefArgs = false; break;
        case 'S': d.separate = true; break;
        case 2:
            d.excludes = (char **)realloc(d.excludes, (d.nexcludes + 1) * sizeof(char *));
            d.excludes[d.nexcludes++] = strdup(g.arg);
            break;
        case 'X': {
            FILE *f = fopen(g.arg, "r");
            if (!f) {
                fprintf(stderr, "du: %s: %s\n", gnuQuoteMaybe(g.arg, q, sizeof(q)), strerror(errno));
                goto done;
            }
            char line[4096];
            while (fgets(line, sizeof(line), f)) {
                size_t n = strlen(line);
                if (n && line[n - 1] == '\n') line[--n] = '\0';
                if (!n) continue;
                d.excludes = (char **)realloc(d.excludes, (d.nexcludes + 1) * sizeof(char *));
                d.excludes[d.nexcludes++] = strdup(line);
            }
            fclose(f);
            break;
        }
        case 't': {
            const char *p = g.arg;
            bool neg = *p == '-';
            if (neg) p++;
            char *end;
            errno = 0;
            uintmax_t v = strtoumax(p, &end, 10);
            uintmax_t mult = 1;
            if (*end) {
                static const char pw[] = "KMGTPEZYRQ";
                char up = *end == 'k' ? 'K' : *end;
                const char *pos = strchr(pw, up);
                unsigned base = 1024;
                if (pos && !strcmp(end + 1, "B")) base = 1000;
                else if (pos && end[1] && strcmp(end + 1, "iB")) pos = NULL;
                if (*end == 'b' && !end[1]) mult = 512;
                else if (!pos) {
                    fprintf(stderr, "du: invalid --threshold argument %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                    goto done;
                } else for (int i = 0; i <= pos - pw; i++) mult *= base;
            }
            if (end == p || (neg && v == 0)) {
                fprintf(stderr, "du: invalid --threshold argument %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto done;
            }
            d.threshold = (intmax_t)(v * mult) * (neg ? -1 : 1);
            d.threshSet = true;
            break;
        }
        case 3: files0 = g.arg; break;
        case 4: d.inodes = true; break;
        case 6:
            d.timeWhich = 'm';
            if (g.arg) {
                if (!strcmp(g.arg, "atime") || !strcmp(g.arg, "access") || !strcmp(g.arg, "use")) d.timeWhich = 'a';
                else if (!strcmp(g.arg, "ctime") || !strcmp(g.arg, "status")) d.timeWhich = 'c';
                else if (strcmp(g.arg, "mtime") && strcmp(g.arg, "modification")) {
                    char q2[64];
                    fprintf(stderr, "du: invalid argument %s for %s\nValid arguments are:\n  - 'atime', 'access', 'use'\n"
                                    "  - 'ctime', 'status'\n",
                            gnuQuoteLocale(g.arg, q, sizeof(q)), gnuQuoteLocale("--time", q2, sizeof(q2)));
                    goto try;
                }
            }
            break;
        case 7: d.timeFmt = g.arg; break;
        case 8:
            fputs("Usage: du [OPTION]... [FILE]...\n"
                  "  or:  du [OPTION]... --files0-from=F\n"
                  "Summarize device usage of the set of FILEs, recursively for directories.\n",
                  stdout);
            status = 0;
            goto done;
        case 9: puts("du (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    if (summarize) {
        if (depthSet && d.maxDepth != 0) {
            fprintf(stderr, "du: warning: summarizing conflicts with --max-depth=%jd\n", d.maxDepth);
            goto try;
        }
        d.maxDepth = 0;
    }
    if (summarize && d.all) {
        fputs("du: cannot both summarize and show all entries\n", stderr);
        goto try;
    }
    if (files0) {
        if (g.nops) {
            fprintf(stderr, "du: extra operand %s\nfile operands cannot be combined with --files0-from\n",
                    gnuQuoteLocale(g.ops[0], q, sizeof(q)));
            goto try;
        }
        FILE *f = strcmp(files0, "-") ? fopen(files0, "r") : stdin;
        if (!f) {
            fprintf(stderr, "du: cannot open %s for reading: %s\n", gnuQuote(files0, q, sizeof(q)), strerror(errno));
            goto done;
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        while ((n = getdelim(&line, &cap, '\0', f)) > 0) {
            if (line[n - 1] == '\0') n--;
            names = (char **)realloc(names, (nnames + 1) * sizeof(char *));
            names[nnames++] = strndup(line, (size_t)n);
        }
        free(line);
        if (f != stdin) fclose(f);
        d.hashAll = true;
    } else if (g.nops == 0) {
        names = (char **)malloc(sizeof(char *));
        names[nnames++] = strdup(".");
    } else {
        for (int i = 0; i < g.nops; i++) {
            names = (char **)realloc(names, (nnames + 1) * sizeof(char *));
            names[nnames++] = strdup(g.ops[i]);
        }
        d.hashAll = g.nops > 1;
    }
    DuSum grand = {0, {0, 0}};
    for (size_t i = 0; i < nnames; i++) {
        DuSum s;
        if (!*names[i]) {
            fputs("du: invalid zero-length file name\n", stderr);
            d.status = 1;
            continue;
        }
        if (duVisit(&d, names[i], 0, &s)) {
            grand.size += s.size;
            duTimeMax(&grand.tmax, s.tmax);
        }
    }
    if (d.total) {
        bool th = d.threshSet;
        d.threshSet = false;
        duPrint(&d, &grand, "total");
        d.threshSet = th;
    }
    status = d.status;
    goto done;
try:
    fputs("Try 'du --help' for more information.\n", stderr);
    status = 1;
done:
    for (size_t i = 0; i < nnames; i++) free(names[i]);
    free(names);
    for (size_t i = 0; i < d.nexcludes; i++) free(d.excludes[i]);
    free(d.excludes);
    free(d.seen);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("du", errno);
        status = 1;
    }
    return status;
}
