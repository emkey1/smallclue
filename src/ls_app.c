/*
 * ls: list directory contents, compatible with GNU coreutils 9 (C and
 * C.UTF-8 locales).
 *
 * The ls this replaces knew a dozen options and its own layouts: no -x, -m,
 * -p, -F classes beyond a few, -g/-o/-G, -s, -k, --si, --time-style,
 * --full-time, -c/-u times, quoting styles, -I/--hide/-B, -T/-w; it laid
 * columns out its own way and exited 1 for a missing operand. This follows
 * GNU's ls.c where it decides what is printed: the column search
 * (calculate_columns) and tab-stop padding, -m wrapping, long-format field
 * widths (taken over every command-line operand, directories included, as
 * GNU does), human-readable sizes rounded up, recent-versus-old dates, total
 * lines, -R headers and blank lines, the quoting styles with GNU's alignment
 * of unquoted names, indicators, LS_COLORS, sort keys and their tie-breaks,
 * and the exit statuses (2 for an operand that cannot be accessed, 1 for a
 * subdirectory).
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ls_app.h"
#include "gnu_size.h"
#include "gnu_util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define LS_ATIM(st) ((st)->st_atimespec)
#define LS_MTIM(st) ((st)->st_mtimespec)
#define LS_CTIM(st) ((st)->st_ctimespec)
#define LS_BTIM(st) ((st)->st_birthtimespec)
#else
#define LS_ATIM(st) ((st)->st_atim)
#define LS_MTIM(st) ((st)->st_mtim)
#define LS_CTIM(st) ((st)->st_ctim)
#define LS_BTIM(st) ((st)->st_mtim)
#endif

enum { F_LONG, F_ONE, F_COLUMNS, F_ACROSS, F_COMMAS };
enum { S_NAME, S_NONE, S_SIZE, S_TIME, S_VERSION, S_EXT, S_WIDTH };
enum { Q_LITERAL, Q_SHELL, Q_SHELL_ALWAYS, Q_SHELL_ESCAPE, Q_SHELL_ESCAPE_ALWAYS, Q_C, Q_C_MAYBE, Q_ESCAPE, Q_LOCALE,
       Q_CLOCALE };
enum { I_NONE, I_SLASH, I_FILE_TYPE, I_CLASSIFY };

typedef struct {
    char *name;            /* as shown */
    char *path;            /* for system calls */
    struct stat st;
    bool statOk;
    char *link;            /* symlink target text */
    bool linkOk;
    mode_t linkMode;
    bool cmdline;
} LsFile;

typedef struct {
    LsFile *v;
    size_t n, cap;
} LsFiles;

typedef struct {
    /* options */
    int format, sort, quoting, indicator;
    bool all, almostAll, ignoreBackups, dirsAsFiles, recursive, reverse, inode, size, numeric;
    bool showOwner, showGroup, human, si, hideControl, groupDirsFirst, zero, fullTime;
    char timeKind;         /* 'm', 'a', 'c', 'b' */
    char deref;            /* 'L', 'H', 'd' (command-line links to dirs), 0 */
    bool color;
    const char *timeRecent, *timeOld;
    char timeBuf[256];
    uintmax_t blockSize;   /* -s and total */
    bool blockSuffix;
    uintmax_t sizeBlock;   /* -l size column: 1 unless --block-size */
    bool sizeSuffix;
    char suffixLetter;
    size_t lineLength;
    bool noWidth;          /* -w 0: no limit, and GNU then pads with spaces only */
    int tabSize;
    char **ignore, **hide;
    size_t nIgnore, nHide;
    /* colours */
    char *colorBuf;
    char *colorCodes[32];
    char **extPat, **extCode;
    size_t nExt;
    bool usedColor;
    /* state */
    int status;
    bool printedSomething;
    struct timespec now;
    /* per listing */
    int wInode, wBlocks, wNlink, wOwner, wGroup, wSize, wMajor, wMinor;
    bool someQuoted;
} Ls;

enum { C_LC, C_RC, C_EC, C_RS, C_NO, C_FI, C_DI, C_LN, C_PI, C_SO, C_BD, C_CD, C_MI, C_OR, C_EX, C_DO,
       C_SU, C_SG, C_ST, C_OW, C_TW, C_CA, C_MH, C_CL, C_N };
static const char *const lsColorNames[] = {"lc", "rc", "ec", "rs", "no", "fi", "di", "ln", "pi", "so", "bd", "cd",
                                           "mi", "or", "ex", "do", "su", "sg", "st", "ow", "tw", "ca", "mh", "cl"};

/* --- Quoting (gnulib quotearg, as ls uses it). --- */

typedef struct {
    char *s;
    size_t n, cap;
} LsBuf;

static void lbPut(LsBuf *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->n + n + 1) cap *= 2;
        char *v = (char *)realloc(b->s, cap);
        if (!v) return;
        b->s = v;
        b->cap = cap;
    }
    memcpy(b->s + b->n, s, n);
    b->n += n;
    b->s[b->n] = '\0';
}

static void lbPutc(LsBuf *b, char c) {
    lbPut(b, &c, 1);
}

static size_t lsUtf8Len(const unsigned char *s, size_t n) {
    if (s[0] < 0x80) return 1;
    size_t k = (s[0] & 0xe0) == 0xc0 ? 2 : (s[0] & 0xf0) == 0xe0 ? 3 : (s[0] & 0xf8) == 0xf0 ? 4 : 0;
    if (k == 0 || k > n) return 0;
    for (size_t i = 1; i < k; i++)
        if ((s[i] & 0xc0) != 0x80) return 0;
    return k;
}

static bool lsShellSpecial(unsigned char c, size_t i) {
    if (c == '#' || c == '~') return i == 0;
    return strchr(" \t\n!\"$&'()*;<=>?[\\]^`{|}", c) != NULL && c != 0;
}

/* Appends `name` quoted per the style; returns whether outer quotes were used. */
static bool lsQuote(const Ls *ls, const char *name, LsBuf *out) {
    const unsigned char *s = (const unsigned char *)name;
    size_t len = strlen(name);
    int style = ls->quoting;
    bool utf8 = gnuUtf8Locale();
    if (style == Q_LITERAL) {
        for (size_t i = 0; i < len;) {
            size_t k = utf8 ? lsUtf8Len(s + i, len - i) : 1;
            if (k == 0) k = 1;
            bool printable = k > 1 || isprint(s[i]) || (!utf8 && s[i] >= 0x80);
            if (!printable && ls->hideControl) lbPutc(out, '?');
            else lbPut(out, name + i, k);
            i += k;
        }
        return false;
    }
    if (style == Q_C_MAYBE) {
        bool plain = true;
        for (size_t i = 0; i < len; i++)
            if (s[i] == '"' || s[i] == '\\' || (s[i] < 0x80 && !isprint(s[i]))) plain = false;
        if (plain) {
            lbPut(out, name, len);
            return false;
        }
        style = Q_C;
    }
    if (style == Q_C || style == Q_ESCAPE) {
        bool c = style == Q_C;
        if (c) lbPutc(out, '"');
        for (size_t i = 0; i < len;) {
            size_t k = utf8 ? lsUtf8Len(s + i, len - i) : 1;
            if (k > 1) { lbPut(out, name + i, k); i += k; continue; }
            unsigned char ch = s[i++];
            const char *esc = NULL;
            switch (ch) {
            case '\a': esc = "\\a"; break;
            case '\b': esc = "\\b"; break;
            case '\f': esc = "\\f"; break;
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            case '\v': esc = "\\v"; break;
            case '\\': esc = "\\\\"; break;
            case '"': if (c) esc = "\\\""; break;
            case ' ': if (!c) esc = "\\ "; break;
            default: break;
            }
            if (esc) { lbPut(out, esc, strlen(esc)); continue; }
            if (!isprint(ch)) {
                char o[8];
                snprintf(o, sizeof(o), "\\%03o", ch);
                lbPut(out, o, 4);
                continue;
            }
            lbPutc(out, (char)ch);
        }
        if (c) lbPutc(out, '"');
        return c;
    }
    if (style == Q_LOCALE || style == Q_CLOCALE) {
        lbPut(out, utf8 ? "\xe2\x80\x98" : "'", utf8 ? 3 : 1);
        for (size_t i = 0; i < len;) {
            size_t k = utf8 ? lsUtf8Len(s + i, len - i) : 1;
            if (k > 1) { lbPut(out, name + i, k); i += k; continue; }
            unsigned char ch = s[i++];
            if (ch == '\\') lbPut(out, "\\\\", 2);
            else if (ch == '\n') lbPut(out, "\\n", 2);
            else if (ch == '\t') lbPut(out, "\\t", 2);
            else if (!isprint(ch)) { char o[8]; snprintf(o, sizeof(o), "\\%03o", ch); lbPut(out, o, 4); }
            else lbPutc(out, (char)ch);
        }
        lbPut(out, utf8 ? "\xe2\x80\x99" : "'", utf8 ? 3 : 1);
        return true;
    }
    /* The shell styles. */
    bool escape = style == Q_SHELL_ESCAPE || style == Q_SHELL_ESCAPE_ALWAYS;
    bool always = style == Q_SHELL_ALWAYS || style == Q_SHELL_ESCAPE_ALWAYS;
    bool needs = always || len == 0, single = false, control = false;
    for (size_t i = 0; i < len;) {
        size_t k = utf8 ? lsUtf8Len(s + i, len - i) : 1;
        if (k > 1) { i += k; continue; }
        unsigned char ch = s[i];
        if (ch == '\'') single = true;
        if (!isprint(ch) && !(!utf8 && ch >= 0x80)) control = true;
        else if (lsShellSpecial(ch, i)) needs = true;
        i++;
    }
    if (control && !escape && ls->hideControl) {
        /* -q: control characters become '?', which itself needs quoting */
        needs = true;
    }
    if (control && escape) needs = true;
    if (!needs) {
        lbPut(out, name, len);
        return false;
    }
    /* "it's" is written in double quotes when nothing else needs them. */
    if (single && !control && !strpbrk(name, "\"$`\\!")) {
        lbPutc(out, '"');
        lbPut(out, name, len);
        lbPutc(out, '"');
        return true;
    }
    lbPutc(out, '\'');
    for (size_t i = 0; i < len;) {
        size_t k = utf8 ? lsUtf8Len(s + i, len - i) : 1;
        if (k > 1) { lbPut(out, name + i, k); i += k; continue; }
        unsigned char ch = s[i++];
        if (ch == '\'') {
            lbPut(out, "'\\''", 4);
        } else if (!isprint(ch) && !(!utf8 && ch >= 0x80)) {
            if (escape) {
                char e[16];
                const char *named = ch == '\n' ? "\\n" : ch == '\t' ? "\\t" : ch == '\r' ? "\\r" : ch == '\a' ? "\\a"
                                  : ch == '\b' ? "\\b" : ch == '\f' ? "\\f" : ch == '\v' ? "\\v" : NULL;
                if (named) snprintf(e, sizeof(e), "'$'%s''", named);
                else snprintf(e, sizeof(e), "'$'\\%03o''", ch);
                lbPut(out, e, strlen(e));
            } else {
                lbPutc(out, ls->hideControl ? '?' : (char)ch);
            }
        } else {
            lbPutc(out, (char)ch);
        }
    }
    lbPutc(out, '\'');
    /* '' left by an escape at either end is redundant, as quotearg drops it */
    if (out->n >= 2 && !memcmp(out->s + out->n - 2, "''", 2) && out->n >= 3 && out->s[out->n - 3] == '\'') {
        out->n -= 2;
        out->s[out->n] = '\0';
    }
    return true;
}

static size_t lsWidth(const char *s) {
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xc0) != 0x80) w++;
    return w;
}

/* --- Sizes. --- */

/* gnulib human_readable with ceiling rounding, as ls -h/--si/-s print. */
static void lsHuman(uintmax_t n, uintmax_t fromBlock, uintmax_t toBlock, bool autoscale, unsigned base, char suffix,
                    char *out, size_t size) {
    /* amount in units of toBlock, rounded up */
    long double v = (long double)n * (long double)fromBlock;
    if (!autoscale) {
        uintmax_t q = (uintmax_t)(v / toBlock);
        if ((long double)q * toBlock < v) q++;
        if (suffix) snprintf(out, size, "%ju%c", q, suffix);
        else snprintf(out, size, "%ju", q);
        return;
    }
    static const char powers[] = "KMGTPEZYRQ";
    if (v < base) {
        snprintf(out, size, "%ju", (uintmax_t)v + (v > (uintmax_t)v ? 1 : 0));
        return;
    }
    int e = 0;
    while (v >= base && e < 10) { v /= base; e++; }
    char letter = powers[e - 1];
    if (base == 1000 && e == 1) letter = 'k';
    if (v < 10) {
        long double tenths = v * 10;
        uintmax_t t = (uintmax_t)tenths;
        if ((long double)t < tenths) t++;
        if (t >= 100) {
            /* rounded up to 10.0: shown without the decimal */
            snprintf(out, size, "%ju%c", t / 10, letter);
        } else {
            snprintf(out, size, "%ju.%ju%c", t / 10, t % 10, letter);
        }
        return;
    }
    uintmax_t i = (uintmax_t)v;
    if ((long double)i < v) i++;
    if (i >= base && e < 10) {
        letter = powers[e];
        snprintf(out, size, "1.0%c", letter);
        return;
    }
    snprintf(out, size, "%ju%c", i, letter);
}

static void lsBlocks(const Ls *ls, uintmax_t blocks512, char *out, size_t size) {
    if (ls->human || ls->si) lsHuman(blocks512, 512, 1, true, ls->si ? 1000 : 1024, 0, out, size);
    else lsHuman(blocks512, 512, ls->blockSize, false, 1024, ls->blockSuffix ? ls->suffixLetter : 0, out, size);
}

static void lsSize(const Ls *ls, uintmax_t bytes, char *out, size_t size) {
    if (ls->human || ls->si) lsHuman(bytes, 1, 1, true, ls->si ? 1000 : 1024, 0, out, size);
    else lsHuman(bytes, 1, ls->sizeBlock, false, 1024, ls->sizeSuffix ? ls->suffixLetter : 0, out, size);
}

/* --- Files. --- */

static void lsPush(LsFiles *fs, LsFile f) {
    if (fs->n == fs->cap) {
        fs->cap = fs->cap ? fs->cap * 2 : 64;
        LsFile *v = (LsFile *)realloc(fs->v, fs->cap * sizeof(LsFile));
        if (!v) return;
        fs->v = v;
    }
    fs->v[fs->n++] = f;
}

static void lsFreeFiles(LsFiles *fs) {
    for (size_t i = 0; i < fs->n; i++) {
        free(fs->v[i].name);
        free(fs->v[i].path);
        free(fs->v[i].link);
    }
    fs->n = 0;
}

static struct timespec lsTime(const Ls *ls, const struct stat *st) {
    switch (ls->timeKind) {
    case 'a': return LS_ATIM(st);
    case 'c': return LS_CTIM(st);
    case 'b': return LS_BTIM(st);
    default: return LS_MTIM(st);
    }
}

static bool lsIsDir(const LsFile *f) {
    return f->statOk && S_ISDIR(f->st.st_mode);
}

/* Fills f's stat; false (with a message) when it cannot be had. */
static bool lsStat(Ls *ls, LsFile *f, bool follow, bool cmdline) {
    char q[4096];
    int r = follow ? stat(f->path, &f->st) : lstat(f->path, &f->st);
    if (r != 0 && follow && cmdline) {
        int err = errno;
        if (lstat(f->path, &f->st) == 0 && S_ISLNK(f->st.st_mode) && ls->deref != 'L') {
            r = 0;
        } else {
            errno = err;
        }
    }
    if (r != 0) {
        fprintf(stderr, "ls: cannot access %s: %s\n", gnuQuote(f->name, q, sizeof(q)), strerror(errno));
        ls->status = cmdline ? 2 : (ls->status ? ls->status : 1);
        f->statOk = false;
        return false;
    }
    f->statOk = true;
    if (S_ISLNK(f->st.st_mode) && (ls->format == F_LONG || ls->indicator == I_CLASSIFY || ls->indicator == I_FILE_TYPE ||
                                   ls->color)) {
        char buf[PATH_MAX];
        ssize_t n = readlink(f->path, buf, sizeof(buf) - 1);
        if (n >= 0) {
            buf[n] = '\0';
            f->link = strdup(buf);
        }
        struct stat t;
        if (stat(f->path, &t) == 0) {
            f->linkOk = true;
            f->linkMode = t.st_mode;
        }
    }
    return true;
}

/* --- Sorting. --- */

static int lsVerOrder(const char *s, size_t pos, size_t len) {
    if (pos == len) return -1;
    unsigned char c = (unsigned char)s[pos];
    if (isdigit(c)) return 0;
    if (isalpha(c)) return c;
    if (c == '~') return -2;
    return c + UCHAR_MAX + 1;
}

static int lsVerRev(const char *a, size_t al, const char *b, size_t bl) {
    size_t i = 0, j = 0;
    while (i < al || j < bl) {
        int first = 0;
        while ((i < al && !isdigit((unsigned char)a[i])) || (j < bl && !isdigit((unsigned char)b[j]))) {
            int x = lsVerOrder(a, i, al), y = lsVerOrder(b, j, bl);
            if (x != y) return x - y;
            i++;
            j++;
        }
        while (i < al && a[i] == '0') i++;
        while (j < bl && b[j] == '0') j++;
        while (i < al && j < bl && isdigit((unsigned char)a[i]) && isdigit((unsigned char)b[j])) {
            if (!first) first = (unsigned char)a[i] - (unsigned char)b[j];
            i++;
            j++;
        }
        if (i < al && isdigit((unsigned char)a[i])) return 1;
        if (j < bl && isdigit((unsigned char)b[j])) return -1;
        if (first) return first;
    }
    return 0;
}

static size_t lsVerPrefix(const char *s, size_t n) {
    size_t prefix = 0;
    for (size_t i = 0;;) {
        if (i == n) return prefix;
        i++;
        prefix = i;
        while (i + 1 < n && s[i] == '.' && (isalpha((unsigned char)s[i + 1]) || s[i + 1] == '~'))
            for (i += 2; i < n && (isalnum((unsigned char)s[i]) || s[i] == '~'); i++) {}
    }
}

static int lsFilevercmp(const char *a, const char *b) {
    size_t al = strlen(a), bl = strlen(b);
    if (!al) return -(bl != 0);
    if (!bl) return 1;
    if (a[0] == '.') {
        if (b[0] != '.') return -1;
        if (al == 1) return -(bl != 1);
        if (bl == 1) return 1;
        bool ad = a[1] == '.' && al == 2, bd = b[1] == '.' && bl == 2;
        if (ad) return -!bd;
        if (bd) return 1;
    } else if (b[0] == '.') {
        return 1;
    }
    size_t ap = lsVerPrefix(a, al), bp = lsVerPrefix(b, bl);
    int r = lsVerRev(a, ap, b, bp);
    return r || (ap == al && bp == bl) ? r : lsVerRev(a, al, b, bl);
}

typedef struct {
    const Ls *ls;
} LsSortCtx;

static const Ls *lsSortLs;   /* qsort has no context; set around each sort */

static int lsCmpName(const LsFile *a, const LsFile *b) {
    return strcmp(a->name, b->name);
}

static int lsCompare(const void *pa, const void *pb) {
    const LsFile *a = (const LsFile *)pa, *b = (const LsFile *)pb;
    const Ls *ls = lsSortLs;
    if (ls->groupDirsFirst) {
        bool ad = lsIsDir(a) || (a->linkOk && S_ISDIR(a->linkMode)), bd = lsIsDir(b) || (b->linkOk && S_ISDIR(b->linkMode));
        if (ad != bd) return ad ? -1 : 1;
    }
    int r = 0;
    switch (ls->sort) {
    case S_SIZE:
        if (a->st.st_size != b->st.st_size) r = a->st.st_size > b->st.st_size ? -1 : 1;
        else r = lsCmpName(a, b);
        break;
    case S_TIME: {
        struct timespec x = lsTime(ls, &a->st), y = lsTime(ls, &b->st);
        if (x.tv_sec != y.tv_sec) r = x.tv_sec > y.tv_sec ? -1 : 1;
        else if (x.tv_nsec != y.tv_nsec) r = x.tv_nsec > y.tv_nsec ? -1 : 1;
        else r = lsCmpName(a, b);
        break;
    }
    case S_VERSION:
        r = lsFilevercmp(a->name, b->name);
        if (!r) r = lsCmpName(a, b);
        break;
    case S_EXT: {
        const char *xa = strrchr(a->name, '.'), *xb = strrchr(b->name, '.');
        r = strcmp(xa ? xa : "", xb ? xb : "");
        if (!r) r = lsCmpName(a, b);
        break;
    }
    case S_WIDTH: {
        size_t wa = lsWidth(a->name), wb = lsWidth(b->name);
        r = wa != wb ? (wa < wb ? -1 : 1) : lsCmpName(a, b);
        break;
    }
    default:
        r = lsCmpName(a, b);
        break;
    }
    return ls->reverse ? -r : r;
}

static void lsSort(Ls *ls, LsFiles *fs) {
    if (ls->sort == S_NONE) {
        if (ls->groupDirsFirst) {
            /* stable partition: directories first, order kept */
            LsFile *tmp = (LsFile *)malloc(fs->n * sizeof(LsFile));
            if (!tmp) return;
            size_t k = 0;
            for (int pass = 0; pass < 2; pass++)
                for (size_t i = 0; i < fs->n; i++) {
                    bool d = lsIsDir(&fs->v[i]) || (fs->v[i].linkOk && S_ISDIR(fs->v[i].linkMode));
                    if (d == (pass == 0)) tmp[k++] = fs->v[i];
                }
            memcpy(fs->v, tmp, fs->n * sizeof(LsFile));
            free(tmp);
        }
        return;
    }
    lsSortLs = ls;
    qsort(fs->v, fs->n, sizeof(LsFile), lsCompare);
    lsSortLs = NULL;
}

/* --- Colours. --- */

static void lsParseColors(Ls *ls) {
    const char *env = getenv("LS_COLORS");
    if (!env || !*env) {
        ls->color = false;   /* GNU 9: no LS_COLORS, no colour */
        return;
    }
    ls->colorBuf = strdup(env);
    if (!ls->colorBuf) { ls->color = false; return; }
    static const char *const defaults[C_N] = {"\033[", "m", NULL, "0", NULL, NULL, "01;34", "01;36", "33", "01;35",
                                              "01;33", "01;33", NULL, NULL, "01;32", "01;35", "37;41", "30;43",
                                              "37;44", "34;42", "30;42", NULL, NULL, "\033[K"};
    for (int i = 0; i < C_N; i++) ls->colorCodes[i] = (char *)defaults[i];
    char *save = NULL;
    for (char *item = strtok_r(ls->colorBuf, ":", &save); item; item = strtok_r(NULL, ":", &save)) {
        char *eq = strchr(item, '=');
        if (!eq) continue;
        *eq = '\0';
        char *val = eq + 1;
        if (item[0] == '*') {
            char **p = (char **)realloc(ls->extPat, (ls->nExt + 1) * sizeof(char *));
            char **c = (char **)realloc(ls->extCode, (ls->nExt + 1) * sizeof(char *));
            if (p) ls->extPat = p;
            if (c) ls->extCode = c;
            if (p && c) {
                ls->extPat[ls->nExt] = item + 1;
                ls->extCode[ls->nExt] = val;
                ls->nExt++;
            }
            continue;
        }
        for (int i = 0; i < C_N; i++)
            if (!strcmp(item, lsColorNames[i])) ls->colorCodes[i] = val;
    }
}

static const char *lsColorFor(const Ls *ls, const LsFile *f) {
    const char *const *cc = (const char *const *)ls->colorCodes;
    if (!f->statOk) return cc[C_MI];
    mode_t m = f->st.st_mode;
    if (S_ISLNK(m)) {
        if (!f->linkOk && cc[C_OR]) return cc[C_OR];
        return cc[C_LN];
    }
    if (S_ISDIR(m)) {
        if ((m & S_ISVTX) && (m & S_IWOTH) && cc[C_TW]) return cc[C_TW];
        if ((m & S_IWOTH) && cc[C_OW]) return cc[C_OW];
        if ((m & S_ISVTX) && cc[C_ST]) return cc[C_ST];
        return cc[C_DI];
    }
    if (S_ISFIFO(m)) return cc[C_PI];
    if (S_ISSOCK(m)) return cc[C_SO];
    if (S_ISBLK(m)) return cc[C_BD];
    if (S_ISCHR(m)) return cc[C_CD];
    if (S_ISREG(m)) {
        if ((m & S_ISUID) && cc[C_SU]) return cc[C_SU];
        if ((m & S_ISGID) && cc[C_SG]) return cc[C_SG];
        if ((m & 0111) && cc[C_EX]) return cc[C_EX];
        size_t nl = strlen(f->name);
        for (size_t i = ls->nExt; i-- > 0;) {
            size_t pl = strlen(ls->extPat[i]);
            if (pl <= nl && !strcmp(f->name + nl - pl, ls->extPat[i])) return ls->extCode[i];
        }
        return cc[C_FI];
    }
    return cc[C_FI];
}

static void lsColorStart(Ls *ls, const char *code) {
    const char *const *cc = (const char *const *)ls->colorCodes;
    if (!ls->usedColor) {
        /* GNU resets once, before the first coloured name */
        fputs(cc[C_LC], stdout);
        fputs(cc[C_RS] ? cc[C_RS] : "0", stdout);
        fputs(cc[C_RC], stdout);
        ls->usedColor = true;
    }
    fputs(cc[C_LC], stdout);
    fputs(code, stdout);
    fputs(cc[C_RC], stdout);
}

static void lsColorEnd(Ls *ls) {
    const char *const *cc = (const char *const *)ls->colorCodes;
    if (cc[C_EC]) {
        fputs(cc[C_EC], stdout);
    } else {
        fputs(cc[C_LC], stdout);
        fputs(cc[C_RS] ? cc[C_RS] : "0", stdout);
        fputs(cc[C_RC], stdout);
    }
}

/* --- Printing names. --- */

static char lsIndicatorChar(const Ls *ls, mode_t m, bool statOk) {
    if (ls->indicator == I_NONE || !statOk) return 0;
    if (S_ISDIR(m)) return '/';
    if (ls->indicator == I_SLASH) return 0;
    if (S_ISLNK(m)) return '@';
    if (S_ISFIFO(m)) return '|';
    if (S_ISSOCK(m)) return '=';
    if (S_ISREG(m) && ls->indicator == I_CLASSIFY && (m & 0111)) return '*';
    return 0;
}

/* The width the name and its decorations take in a listing. */
static size_t lsFrillsWidth(const Ls *ls, const LsFile *f) {
    LsBuf b = {NULL, 0, 0};
    bool quoted = lsQuote(ls, f->name, &b);
    size_t w = b.s ? lsWidth(b.s) : 0;
    free(b.s);
    if (ls->someQuoted && !quoted) w++;
    if (ls->inode) w += (size_t)ls->wInode + 1;
    if (ls->size) w += (size_t)ls->wBlocks + 1;
    if (lsIndicatorChar(ls, f->st.st_mode, f->statOk) && !(ls->format == F_LONG && S_ISLNK(f->st.st_mode))) w++;
    return w;
}

static void lsPrintName(Ls *ls, const LsFile *f, const char *name, mode_t mode, bool statOk, const char *code, bool align) {
    LsBuf b = {NULL, 0, 0};
    bool quoted = lsQuote(ls, name, &b);
    if (align && ls->someQuoted && !quoted) putchar(' ');
    (void)f;
    if (ls->color && code && *code) {
        lsColorStart(ls, code);
        fputs(b.s ? b.s : "", stdout);
        lsColorEnd(ls);
    } else {
        fputs(b.s ? b.s : "", stdout);
    }
    free(b.s);
    (void)mode;
    (void)statOk;
}

static void lsPrintFrills(Ls *ls, const LsFile *f) {
    char buf[64];
    if (ls->inode) {
        snprintf(buf, sizeof(buf), "%ju", (uintmax_t)f->st.st_ino);
        printf("%*s ", ls->wInode, f->statOk ? buf : "?");
    }
    if (ls->size) {
        if (f->statOk) lsBlocks(ls, (uintmax_t)f->st.st_blocks, buf, sizeof(buf));
        printf("%*s ", ls->wBlocks, f->statOk ? buf : "?");
    }
    lsPrintName(ls, f, f->name, f->st.st_mode, f->statOk, ls->color ? lsColorFor(ls, f) : NULL, true);
    char ind = lsIndicatorChar(ls, f->st.st_mode, f->statOk);
    if (ind) putchar(ind);
}

/* --- Widths for a listing. --- */

static void lsComputeWidths(Ls *ls, const LsFiles *fs) {
    ls->wInode = ls->wBlocks = ls->wNlink = ls->wOwner = ls->wGroup = ls->wSize = ls->wMajor = ls->wMinor = 0;
    ls->someQuoted = false;
    bool alignQuotes = ls->format != F_COMMAS && ls->format != F_ONE &&
                       (ls->quoting == Q_SHELL || ls->quoting == Q_SHELL_ESCAPE);
    char buf[128];
    for (size_t i = 0; i < fs->n; i++) {
        const LsFile *f = &fs->v[i];
        if (alignQuotes && !ls->someQuoted) {
            LsBuf b = {NULL, 0, 0};
            if (lsQuote(ls, f->name, &b)) ls->someQuoted = true;
            free(b.s);
        }
        if (!f->statOk) continue;
        int n;
        n = snprintf(buf, sizeof(buf), "%ju", (uintmax_t)f->st.st_ino);
        if (n > ls->wInode) ls->wInode = n;
        lsBlocks(ls, (uintmax_t)f->st.st_blocks, buf, sizeof(buf));
        n = (int)strlen(buf);
        if (n > ls->wBlocks) ls->wBlocks = n;
        if (ls->format != F_LONG) continue;
        n = snprintf(buf, sizeof(buf), "%ju", (uintmax_t)f->st.st_nlink);
        if (n > ls->wNlink) ls->wNlink = n;
        struct passwd *pw = ls->numeric ? NULL : getpwuid(f->st.st_uid);
        n = pw ? (int)lsWidth(pw->pw_name) : snprintf(buf, sizeof(buf), "%u", (unsigned)f->st.st_uid);
        if (n > ls->wOwner) ls->wOwner = n;
        struct group *gr = ls->numeric ? NULL : getgrgid(f->st.st_gid);
        n = gr ? (int)lsWidth(gr->gr_name) : snprintf(buf, sizeof(buf), "%u", (unsigned)f->st.st_gid);
        if (n > ls->wGroup) ls->wGroup = n;
        if (S_ISCHR(f->st.st_mode) || S_ISBLK(f->st.st_mode)) {
            unsigned maj = (unsigned)((f->st.st_rdev >> 8) & 0xfff) | (unsigned)((f->st.st_rdev >> 32) & ~0xfffu);
            unsigned min = (unsigned)(f->st.st_rdev & 0xff) | (unsigned)((f->st.st_rdev >> 12) & ~0xffu);
#if defined(__APPLE__)
            maj = (unsigned)major(f->st.st_rdev);
            min = (unsigned)minor(f->st.st_rdev);
#endif
            n = snprintf(buf, sizeof(buf), "%u", maj);
            if (n > ls->wMajor) ls->wMajor = n;
            n = snprintf(buf, sizeof(buf), "%u", min);
            if (n > ls->wMinor) ls->wMinor = n;
            if (ls->wMajor + 2 + ls->wMinor > ls->wSize) ls->wSize = ls->wMajor + 2 + ls->wMinor;
        } else {
            lsSize(ls, (uintmax_t)f->st.st_size, buf, sizeof(buf));
            n = (int)strlen(buf);
            if (n > ls->wSize) ls->wSize = n;
        }
    }
}

/* --- Long format. --- */

static void lsModeString(mode_t m, char out[11]) {
    out[0] = S_ISDIR(m) ? 'd' : S_ISLNK(m) ? 'l' : S_ISCHR(m) ? 'c' : S_ISBLK(m) ? 'b' : S_ISFIFO(m) ? 'p'
           : S_ISSOCK(m) ? 's' : S_ISREG(m) ? '-' : '?';
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) out[i + 1] = (m & (0400 >> i)) ? rwx[i] : '-';
    if (m & S_ISUID) out[3] = (m & S_IXUSR) ? 's' : 'S';
    if (m & S_ISGID) out[6] = (m & S_IXGRP) ? 's' : 'S';
    if (m & S_ISVTX) out[9] = (m & S_IXOTH) ? 't' : 'T';
    out[10] = '\0';
}

static void lsFormatTime(Ls *ls, struct timespec ts, char *out, size_t size) {
    struct timespec now = ls->now;
    if (ts.tv_sec > now.tv_sec || (ts.tv_sec == now.tv_sec && ts.tv_nsec > now.tv_nsec)) {
        clock_gettime(CLOCK_REALTIME, &ls->now);
        now = ls->now;
    }
    time_t sixAgo = now.tv_sec - 31556952 / 2;
    bool recent = (ts.tv_sec > sixAgo || (ts.tv_sec == sixAgo && ts.tv_nsec > now.tv_nsec)) &&
                  (ts.tv_sec < now.tv_sec || (ts.tv_sec == now.tv_sec && ts.tv_nsec < now.tv_nsec));
    const char *fmt = recent ? ls->timeRecent : ls->timeOld;
    time_t t = ts.tv_sec;
    struct tm tm;
    if (!localtime_r(&t, &tm)) {
        snprintf(out, size, "%jd", (intmax_t)t);
        return;
    }
    /* %N, which strftime lacks, for --full-time */
    char f2[256];
    size_t o = 0;
    for (const char *p = fmt; *p && o + 12 < sizeof(f2); p++) {
        if (p[0] == '%' && p[1] == 'N') {
            o += (size_t)snprintf(f2 + o, sizeof(f2) - o, "%09ld", (long)ts.tv_nsec);
            p++;
        } else if (p[0] == '%' && p[1] == '%') {
            f2[o++] = '%';
            f2[o++] = '%';
            p++;
        } else {
            f2[o++] = *p;
        }
    }
    f2[o] = '\0';
    if (strftime(out, size, f2, &tm) == 0) out[0] = '\0';
}

static void lsPrintLong(Ls *ls, const LsFile *f) {
    char mode[11], buf[64], when[256];
    if (ls->inode) {
        snprintf(buf, sizeof(buf), "%ju", (uintmax_t)f->st.st_ino);
        printf("%*s ", ls->wInode, f->statOk ? buf : "?");
    }
    if (ls->size) {
        if (f->statOk) lsBlocks(ls, (uintmax_t)f->st.st_blocks, buf, sizeof(buf));
        printf("%*s ", ls->wBlocks, f->statOk ? buf : "?");
    }
    if (!f->statOk) {
        printf("l????????? ? ");
    } else {
        lsModeString(f->st.st_mode, mode);
        printf("%s %*ju ", mode, ls->wNlink, (uintmax_t)f->st.st_nlink);
        if (ls->showOwner) {
            struct passwd *pw = ls->numeric ? NULL : getpwuid(f->st.st_uid);
            if (pw) printf("%-*s ", ls->wOwner, pw->pw_name);
            else printf("%-*u ", ls->wOwner, (unsigned)f->st.st_uid);
        }
        if (ls->showGroup) {
            struct group *gr = ls->numeric ? NULL : getgrgid(f->st.st_gid);
            if (gr) printf("%-*s ", ls->wGroup, gr->gr_name);
            else printf("%-*u ", ls->wGroup, (unsigned)f->st.st_gid);
        }
        if (S_ISCHR(f->st.st_mode) || S_ISBLK(f->st.st_mode)) {
            unsigned maj, min;
#if defined(__APPLE__)
            maj = (unsigned)major(f->st.st_rdev);
            min = (unsigned)minor(f->st.st_rdev);
#else
            maj = (unsigned)((f->st.st_rdev >> 8) & 0xfff) | (unsigned)((f->st.st_rdev >> 32) & ~0xfffu);
            min = (unsigned)(f->st.st_rdev & 0xff) | (unsigned)((f->st.st_rdev >> 12) & ~0xffu);
#endif
            printf("%*u, %*u ", ls->wSize - 2 - ls->wMinor, maj, ls->wMinor, min);
        } else {
            lsSize(ls, (uintmax_t)f->st.st_size, buf, sizeof(buf));
            printf("%*s ", ls->wSize, buf);
        }
        lsFormatTime(ls, lsTime(ls, &f->st), when, sizeof(when));
        printf("%s ", when);
    }
    lsPrintName(ls, f, f->name, f->st.st_mode, f->statOk, ls->color ? lsColorFor(ls, f) : NULL, true);
    if (f->statOk && S_ISLNK(f->st.st_mode) && f->link) {
        fputs(" -> ", stdout);
        LsFile target = *f;
        target.name = f->link;
        if (f->linkOk) {
            target.st.st_mode = f->linkMode;
            target.linkOk = false;
        }
        lsPrintName(ls, &target, f->link, f->linkMode, f->linkOk, NULL, false);
        if (f->linkOk && ls->indicator != I_NONE) {
            char ind = lsIndicatorChar(ls, f->linkMode, true);
            if (ind) putchar(ind);
        }
    } else {
        char ind = lsIndicatorChar(ls, f->st.st_mode, f->statOk);
        if (ind) putchar(ind);
    }
}

/* --- Layouts. --- */

static void lsIndent(const Ls *ls, size_t from, size_t to) {
    while (from < to) {
        if (ls->tabSize && !ls->noWidth && to / (size_t)ls->tabSize > (from + 1) / (size_t)ls->tabSize) {
            putchar('\t');
            from += (size_t)ls->tabSize - from % (size_t)ls->tabSize;
        } else {
            putchar(' ');
            from++;
        }
    }
}

/* GNU's calculate_columns. */
static size_t lsColumns(const Ls *ls, const size_t *widths, size_t n, bool byColumns, size_t **colArr) {
    size_t maxIdx = ls->lineLength / 3;
    if (maxIdx == 0) maxIdx = 1;
    size_t maxCols = maxIdx < n ? maxIdx : n;
    if (maxCols == 0) maxCols = 1;
    size_t *lineLen = (size_t *)calloc(maxCols, sizeof(size_t));
    bool *valid = (bool *)calloc(maxCols, sizeof(bool));
    size_t **arr = (size_t **)calloc(maxCols, sizeof(size_t *));
    if (!lineLen || !valid || !arr) { free(lineLen); free(valid); free(arr); return 1; }
    for (size_t i = 0; i < maxCols; i++) {
        valid[i] = true;
        lineLen[i] = (i + 1) * 3;
        arr[i] = (size_t *)malloc((i + 1) * sizeof(size_t));
        for (size_t j = 0; j <= i && arr[i]; j++) arr[i][j] = 3;
    }
    for (size_t f = 0; f < n; f++) {
        for (size_t i = 0; i < maxCols; i++) {
            if (!valid[i] || !arr[i]) continue;
            size_t idx = byColumns ? f / ((n + i) / (i + 1)) : f % (i + 1);
            size_t real = widths[f] + (idx == i ? 0 : 2);
            if (arr[i][idx] < real) {
                lineLen[i] += real - arr[i][idx];
                arr[i][idx] = real;
                valid[i] = lineLen[i] < ls->lineLength;
            }
        }
    }
    size_t cols;
    for (cols = maxCols; cols > 1; cols--)
        if (valid[cols - 1]) break;
    *colArr = arr[cols - 1];
    arr[cols - 1] = NULL;
    for (size_t i = 0; i < maxCols; i++) free(arr[i]);
    free(arr);
    free(lineLen);
    free(valid);
    return cols;
}

static void lsPrintFiles(Ls *ls, LsFiles *fs) {
    if (fs->n == 0) return;
    char eol = ls->zero ? '\0' : '\n';
    if (ls->format == F_LONG || ls->format == F_ONE) {
        for (size_t i = 0; i < fs->n; i++) {
            if (ls->format == F_LONG) lsPrintLong(ls, &fs->v[i]);
            else lsPrintFrills(ls, &fs->v[i]);
            putchar(eol);
        }
        return;
    }
    size_t *w = (size_t *)malloc(fs->n * sizeof(size_t));
    if (!w) return;
    for (size_t i = 0; i < fs->n; i++) w[i] = lsFrillsWidth(ls, &fs->v[i]);
    if (ls->format == F_COMMAS) {
        size_t pos = 0;
        for (size_t i = 0; i < fs->n; i++) {
            size_t len = ls->lineLength ? w[i] : 0;
            if (i != 0) {
                char sep;
                if (!ls->lineLength || pos + len + 2 < ls->lineLength) {
                    pos += 2;
                    sep = ' ';
                } else {
                    pos = 0;
                    sep = eol;
                }
                putchar(',');
                putchar(sep);
            }
            lsPrintFrills(ls, &fs->v[i]);
            pos += len;
        }
        putchar(eol);
        free(w);
        return;
    }
    size_t *col;
    size_t cols = lsColumns(ls, w, fs->n, ls->format == F_COLUMNS, &col);
    if (ls->format == F_COLUMNS) {
        size_t rows = (fs->n + cols - 1) / cols;
        for (size_t row = 0; row < rows; row++) {
            size_t c = 0, pos = 0;
            for (size_t f = row;;) {
                lsPrintFrills(ls, &fs->v[f]);
                size_t nameLen = w[f], maxLen = col ? col[c++] : nameLen + 2;
                f += rows;
                if (f >= fs->n) break;
                lsIndent(ls, pos + nameLen, pos + maxLen);
                pos += maxLen;
            }
            putchar(eol);
        }
    } else {
        size_t pos = 0, nameLen = 0, maxLen = 0;
        lsPrintFrills(ls, &fs->v[0]);
        nameLen = w[0];
        maxLen = col ? col[0] : nameLen + 2;
        for (size_t f = 1; f < fs->n; f++) {
            size_t c = f % cols;
            if (c == 0) {
                putchar(eol);
                pos = 0;
            } else {
                lsIndent(ls, pos + nameLen, pos + maxLen);
                pos += maxLen;
            }
            lsPrintFrills(ls, &fs->v[f]);
            nameLen = w[f];
            maxLen = col ? col[c] : nameLen + 2;
        }
        putchar(eol);
    }
    free(col);
    free(w);
}

/* --- Directories. --- */

static bool lsHidden(const Ls *ls, const char *name) {
    if (name[0] == '.' && !ls->all && !ls->almostAll) return true;
    if (!ls->all && (!strcmp(name, ".") || !strcmp(name, ".."))) return true;
    for (size_t i = 0; i < ls->nIgnore; i++)
        if (fnmatch(ls->ignore[i], name, FNM_PERIOD) == 0) return true;
    if (!ls->all && !ls->almostAll)
        for (size_t i = 0; i < ls->nHide; i++)
            if (fnmatch(ls->hide[i], name, FNM_PERIOD) == 0) return true;
    if (ls->ignoreBackups) {
        size_t n = strlen(name);
        if (n && name[n - 1] == '~') return true;
    }
    return false;
}

static char *lsJoin(const char *dir, const char *name) {
    size_t dl = strlen(dir), nl = strlen(name);
    char *p = (char *)malloc(dl + nl + 2);
    if (!p) return NULL;
    memcpy(p, dir, dl);
    if (dl == 0 || dir[dl - 1] != '/') p[dl++] = '/';
    memcpy(p + dl, name, nl + 1);
    return p;
}

static void lsDir(Ls *ls, const char *name, const char *path, bool cmdline, bool header);

static void lsHeader(Ls *ls, const char *name) {
    if (ls->printedSomething) putchar('\n');
    LsBuf b = {NULL, 0, 0};
    lsQuote(ls, name, &b);
    fputs(b.s ? b.s : "", stdout);
    free(b.s);
    fputs(":\n", stdout);
    ls->printedSomething = true;
}

static void lsDir(Ls *ls, const char *name, const char *path, bool cmdline, bool header) {
    char q[4096];
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "ls: cannot open directory %s: %s\n", gnuQuote(name, q, sizeof(q)), strerror(errno));
        ls->status = cmdline ? 2 : (ls->status > 1 ? ls->status : 1);
        return;
    }
    if (header) lsHeader(ls, name);
    ls->printedSomething = true;
    LsFiles fs = {NULL, 0, 0};
    struct dirent *de;
    while ((de = readdir(d))) {
        if (lsHidden(ls, de->d_name)) continue;
        LsFile f;
        memset(&f, 0, sizeof(f));
        f.name = strdup(de->d_name);
        f.path = lsJoin(path, de->d_name);
        if (!f.name || !f.path) { free(f.name); free(f.path); continue; }
        bool need = ls->format == F_LONG || ls->sort == S_SIZE || ls->sort == S_TIME || ls->recursive ||
                    ls->indicator != I_NONE || ls->color || ls->inode || ls->size || ls->groupDirsFirst || 1;
        if (need && !lsStat(ls, &f, ls->deref == 'L', false)) {
            /* listed anyway, with question marks, as GNU does */
        }
        lsPush(&fs, f);
    }
    closedir(d);
    lsSort(ls, &fs);
    lsComputeWidths(ls, &fs);
    if (ls->format == F_LONG || ls->size) {
        uintmax_t total = 0;
        for (size_t i = 0; i < fs.n; i++)
            if (fs.v[i].statOk) total += (uintmax_t)fs.v[i].st.st_blocks;
        char buf[64];
        lsBlocks(ls, total, buf, sizeof(buf));
        printf("total %s%c", buf, ls->zero ? '\0' : '\n');
    }
    lsPrintFiles(ls, &fs);
    if (ls->recursive) {
        for (size_t i = 0; i < fs.n; i++) {
            LsFile *f = &fs.v[i];
            if (!lsIsDir(f) || !strcmp(f->name, ".") || !strcmp(f->name, "..")) continue;
            char *shown = lsJoin(name, f->name);
            if (shown) lsDir(ls, shown, f->path, false, true);
            free(shown);
        }
    }
    lsFreeFiles(&fs);
    free(fs.v);
}

/* --- Options. --- */

static int lsTry(void) {
    fputs("Try 'ls --help' for more information.\n", stderr);
    return 2;
}

static void lsUsage(void) {
    fputs("Usage: ls [OPTION]... [FILE]...\n"
          "List information about the FILEs (the current directory by default).\n"
          "Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.\n\n"
          "  -a, --all                  do not ignore entries starting with .\n"
          "  -A, --almost-all           do not list implied . and ..\n"
          "  -b, --escape               print C-style escapes for nongraphic characters\n"
          "      --block-size=SIZE      with -l, scale sizes by SIZE when printing them\n"
          "  -B, --ignore-backups       do not list implied entries ending with ~\n"
          "  -c                         with -lt: sort by, and show, ctime\n"
          "  -C                         list entries by columns\n"
          "      --color[=WHEN]         color the output WHEN; more info below\n"
          "  -d, --directory            list directories themselves, not their contents\n"
          "  -f                         same as -a -U\n"
          "  -F, --classify[=WHEN]      append indicator (one of */=>@|) to entries WHEN\n"
          "      --file-type            likewise, except do not append '*'\n"
          "      --format=WORD          across -x, commas -m, horizontal -x, long -l,\n"
          "                             single-column -1, verbose -l, vertical -C\n"
          "      --full-time            like -l --time-style=full-iso\n"
          "  -g                         like -l, but do not list owner\n"
          "      --group-directories-first  group directories before files\n"
          "  -G, --no-group             in a long listing, don't print group names\n"
          "  -h, --human-readable       with -l and -s, print sizes like 1K 234M 2G etc.\n"
          "      --si                   likewise, but use powers of 1000 not 1024\n"
          "  -H, --dereference-command-line  follow symbolic links listed on the command line\n"
          "      --hide=PATTERN         do not list implied entries matching shell PATTERN\n"
          "      --indicator-style=WORD  none, slash (-p), file-type, classify (-F)\n"
          "  -i, --inode                print the index number of each file\n"
          "  -I, --ignore=PATTERN       do not list implied entries matching shell PATTERN\n"
          "  -k, --kibibytes            default to 1024-byte blocks for file system usage\n"
          "  -l                         use a long listing format\n"
          "  -L, --dereference          show information for the file references\n"
          "  -m                         fill width with a comma separated list of entries\n"
          "  -n, --numeric-uid-gid      like -l, but list numeric user and group IDs\n"
          "  -N, --literal              print entry names without quoting\n"
          "  -o                         like -l, but do not list group information\n"
          "  -p, --indicator-style=slash  append / indicator to directories\n"
          "  -q, --hide-control-chars   print ? instead of nongraphic characters\n"
          "      --show-control-chars   show nongraphic characters as-is\n"
          "  -Q, --quote-name           enclose entry names in double quotes\n"
          "      --quoting-style=WORD   literal, locale, shell, shell-always, shell-escape,\n"
          "                             shell-escape-always, c, escape\n"
          "  -r, --reverse              reverse order while sorting\n"
          "  -R, --recursive            list subdirectories recursively\n"
          "  -s, --size                 print the allocated size of each file, in blocks\n"
          "  -S                         sort by file size, largest first\n"
          "      --sort=WORD            none (-U), size (-S), time (-t), version (-v),\n"
          "                             extension (-X), width\n"
          "      --time=WORD            atime -u, access -u, use -u, ctime -c, status -c,\n"
          "                             birth, creation, mtime, modification\n"
          "      --time-style=TIME_STYLE  full-iso, long-iso, iso, locale, or +FORMAT\n"
          "  -t                         sort by time, newest first; see --time\n"
          "  -T, --tabsize=COLS         assume tab stops at each COLS instead of 8\n"
          "  -u                         with -lt: sort by, and show, access time\n"
          "  -U                         do not sort; list entries in directory order\n"
          "  -v                         natural sort of (version) numbers within text\n"
          "  -w, --width=COLS           set output width to COLS.  0 means no limit\n"
          "  -x                         list entries by lines instead of by columns\n"
          "  -X                         sort alphabetically by entry extension\n"
          "      --zero                 end each output line with NUL, not newline\n"
          "  -1                         list one file per line\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n\n"
          "Exit status:\n"
          " 0  if OK,\n"
          " 1  if minor problems (e.g., cannot access subdirectory),\n"
          " 2  if serious trouble (e.g., cannot access command-line argument).\n",
          stdout);
}

static bool lsArgmatch(const char *opt, const char *val, const char *const *names, const int *values, int n, int *out) {
    int found = -1;
    size_t len = strlen(val);
    for (int i = 0; i < n; i++) {
        if (!strcmp(val, names[i])) { *out = values[i]; return true; }
        if (len && !strncmp(names[i], val, len)) {
            if (found >= 0 && values[found] != values[i]) { found = -2; break; }
            if (found != -2) found = i;
        }
    }
    if (found >= 0) { *out = values[found]; return true; }
    char q[256], q2[64];
    fprintf(stderr, "ls: %s argument %s for %s\nValid arguments are:\n", found == -2 ? "ambiguous" : "invalid",
            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale(opt, q2, sizeof(q2)));
    for (int i = 0; i < n; i++) {
        bool same = i > 0 && values[i] == values[i - 1];
        if (!same) fprintf(stderr, "%s  - %s", i ? "\n" : "", gnuQuoteLocale(names[i], q, sizeof(q)));
        else fprintf(stderr, ", %s", gnuQuoteLocale(names[i], q, sizeof(q)));
    }
    fputc('\n', stderr);
    return false;
}

static bool lsTimeStyle(Ls *ls, const char *style) {
    if (!strncmp(style, "posix-", 6)) style += 6;
    if (style[0] == '+') {
        snprintf(ls->timeBuf, sizeof(ls->timeBuf), "%s", style + 1);
        char *nl = strchr(ls->timeBuf, '\n');
        ls->timeRecent = ls->timeOld = ls->timeBuf;
        if (nl) {
            *nl = '\0';
            ls->timeRecent = ls->timeBuf;
            ls->timeOld = nl + 1;
        }
        return true;
    }
    static const char *const names[] = {"full-iso", "long-iso", "iso", "locale"};
    int k = -1;
    for (int i = 0; i < 4; i++)
        if (!strcmp(style, names[i])) k = i;
    if (k < 0) {
        char q[256], q2[64];
        fprintf(stderr, "ls: invalid argument %s for %s\nValid arguments are:\n"
                        "  - [posix-]full-iso\n  - [posix-]long-iso\n  - [posix-]iso\n  - [posix-]locale\n"
                        "  - +FORMAT (e.g., +%%H:%%M) for a 'date'-style format\n",
                gnuQuoteLocale(style, q, sizeof(q)), gnuQuoteLocale("time style", q2, sizeof(q2)));
        return false;
    }
    switch (k) {
    case 0: ls->timeRecent = ls->timeOld = "%Y-%m-%d %H:%M:%S.%N %z"; break;
    case 1: ls->timeRecent = ls->timeOld = "%Y-%m-%d %H:%M"; break;
    case 2: ls->timeRecent = "%m-%d %H:%M"; ls->timeOld = "%Y-%m-%d "; break;
    default: ls->timeRecent = "%b %e %H:%M"; ls->timeOld = "%b %e  %Y"; break;
    }
    return true;
}

static bool lsBlockSize(Ls *ls, const char *s, bool forSizes) {
    char q[256];
    if (!strcmp(s, "human-readable")) { ls->human = true; return true; }
    if (!strcmp(s, "si")) { ls->si = true; return true; }
    const char *p = s;
    if (*p == '\'') p++;
    uintmax_t v = 1;
    char letter = 0;
    if (isdigit((unsigned char)*p)) {
        int r = gnuParseSize(p, &v);
        if (r != 0 || v == 0) {
            fprintf(stderr, "ls: invalid --block-size argument %s\n", gnuQuoteLocale(s, q, sizeof(q)));
            return false;
        }
    } else {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "1%s", p);
        if (gnuParseSize(tmp, &v) != 0) {
            fprintf(stderr, "ls: invalid --block-size argument %s\n", gnuQuoteLocale(s, q, sizeof(q)));
            return false;
        }
        letter = (char)toupper((unsigned char)*p);
    }
    ls->blockSize = v;
    ls->blockSuffix = letter != 0;
    ls->suffixLetter = letter;
    if (forSizes) {
        ls->sizeBlock = v;
        ls->sizeSuffix = letter != 0;
    }
    return true;
}

typedef struct {
    const char *name;
    int c;
    int arg;          /* 0 none, 1 required, 2 optional */
} LsLong;

static const LsLong lsLongs[] = {
    {"all", 'a', 0}, {"almost-all", 'A', 0}, {"author", 1, 0}, {"escape", 'b', 0}, {"block-size", 2, 1},
    {"ignore-backups", 'B', 0}, {"color", 3, 2}, {"colour", 3, 2}, {"directory", 'd', 0}, {"dired", 'D', 0},
    {"classify", 4, 2}, {"file-type", 5, 0}, {"format", 6, 1}, {"full-time", 7, 0},
    {"group-directories-first", 8, 0}, {"no-group", 'G', 0}, {"human-readable", 'h', 0}, {"si", 9, 0},
    {"dereference-command-line", 'H', 0}, {"dereference-command-line-symlink-to-dir", 10, 0},
    {"hide", 11, 1}, {"hyperlink", 12, 2}, {"indicator-style", 13, 1}, {"inode", 'i', 0}, {"ignore", 'I', 1},
    {"kibibytes", 'k', 0}, {"dereference", 'L', 0}, {"numeric-uid-gid", 'n', 0}, {"literal", 'N', 0},
    {"hide-control-chars", 'q', 0}, {"show-control-chars", 14, 0}, {"quote-name", 'Q', 0},
    {"quoting-style", 15, 1}, {"reverse", 'r', 0}, {"recursive", 'R', 0}, {"size", 's', 0}, {"sort", 16, 1},
    {"time", 17, 1}, {"time-style", 18, 1}, {"tabsize", 'T', 1}, {"width", 'w', 1}, {"context", 'Z', 0},
    {"zero", 19, 0}, {"help", 20, 0}, {"version", 21, 0},
};

/* One option; 1 when ls must stop now (status in ls->status). */
static int lsOption(Ls *ls, int c, const char *val, bool *formatSet, bool *quotingSet, bool *hideSet) {
    char q[256];
    switch (c) {
    case 'a': ls->all = true; ls->almostAll = false; break;
    case 'A': ls->almostAll = true; ls->all = false; break;
    case 'b': ls->quoting = Q_ESCAPE; *quotingSet = true; break;
    case 'B': ls->ignoreBackups = true; break;
    case 'c': ls->timeKind = 'c'; break;
    case 'C': ls->format = F_COLUMNS; *formatSet = true; break;
    case 'd': ls->dirsAsFiles = true; break;
    case 'D': break;
    case 'f': ls->all = true; ls->sort = S_NONE; break;
    case 'F': ls->indicator = I_CLASSIFY; break;
    case 'g': ls->format = F_LONG; *formatSet = true; ls->showOwner = false; break;
    case 'G': ls->showGroup = false; break;
    case 'h': ls->human = true; break;
    case 'H': ls->deref = 'H'; break;
    case 'i': ls->inode = true; break;
    case 'I': {
        char **v = (char **)realloc(ls->ignore, (ls->nIgnore + 1) * sizeof(char *));
        if (v) { ls->ignore = v; ls->ignore[ls->nIgnore++] = (char *)val; }
        break;
    }
    case 'k': ls->blockSize = 1024; ls->blockSuffix = false; break;
    case 'l': ls->format = F_LONG; *formatSet = true; break;
    case 'L': ls->deref = 'L'; break;
    case 'm': ls->format = F_COMMAS; *formatSet = true; break;
    case 'n': ls->numeric = true; ls->format = F_LONG; *formatSet = true; break;
    case 'N': ls->quoting = Q_LITERAL; *quotingSet = true; break;
    case 'o': ls->format = F_LONG; *formatSet = true; ls->showGroup = false; break;
    case 'p': ls->indicator = I_SLASH; break;
    case 'q': ls->hideControl = true; *hideSet = true; break;
    case 'Q': ls->quoting = Q_C; *quotingSet = true; break;
    case 'r': ls->reverse = true; break;
    case 'R': ls->recursive = true; break;
    case 's': ls->size = true; break;
    case 'S': ls->sort = S_SIZE; break;
    case 't': ls->sort = S_TIME; break;
    case 'T': {
        char *end;
        long v = strtol(val, &end, 10);
        if (*end || v < 0 || !*val) {
            fprintf(stderr, "ls: invalid tab size: %s\n", gnuQuoteLocale(val, q, sizeof(q)));
            ls->status = 2;
            return 1;
        }
        ls->tabSize = (int)v;
        break;
    }
    case 'u': ls->timeKind = 'a'; break;
    case 'U': ls->sort = S_NONE; break;
    case 'v': ls->sort = S_VERSION; break;
    case 'w': {
        char *end;
        long long v = strtoll(val, &end, 10);
        if (*end || v < 0 || !*val) {
            fprintf(stderr, "ls: invalid line width: %s\n", gnuQuoteLocale(val, q, sizeof(q)));
            ls->status = 2;
            return 1;
        }
        ls->lineLength = v ? (size_t)v : SIZE_MAX / 4;
        if (!v) ls->noWidth = true;
        break;
    }
    case 'x': ls->format = F_ACROSS; *formatSet = true; break;
    case 'X': ls->sort = S_EXT; break;
    case 'Z': break;
    case '1': ls->format = F_ONE; *formatSet = true; break;
    case 1: break;
    case 2: if (!lsBlockSize(ls, val, true)) { ls->status = 2; return 1; } break;
    case 3: {
        if (!val) { ls->color = isatty(1); break; }
        static const char *const n[] = {"always", "yes", "force", "never", "no", "none", "auto", "tty", "if-tty"};
        static const int v[] = {1, 1, 1, 0, 0, 0, 2, 2, 2};
        int k;
        if (!lsArgmatch("--color", val, n, v, 9, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->color = k == 1 || (k == 2 && isatty(1) && getenv("TERM") && strcmp(getenv("TERM"), "dumb"));
        break;
    }
    case 4: {
        if (!val) { ls->indicator = I_CLASSIFY; break; }
        static const char *const n[] = {"always", "yes", "force", "never", "no", "none", "auto", "tty", "if-tty"};
        static const int v[] = {1, 1, 1, 0, 0, 0, 2, 2, 2};
        int k;
        if (!lsArgmatch("--classify", val, n, v, 9, &k)) { lsTry(); ls->status = 1; return 1; }
        if (k == 1 || (k == 2 && isatty(1))) ls->indicator = I_CLASSIFY;
        break;
    }
    case 5: ls->indicator = I_FILE_TYPE; break;
    case 6: {
        static const char *const n[] = {"verbose", "long", "commas", "horizontal", "across", "vertical", "single-column"};
        static const int v[] = {F_LONG, F_LONG, F_COMMAS, F_ACROSS, F_ACROSS, F_COLUMNS, F_ONE};
        int k;
        if (!lsArgmatch("--format", val, n, v, 7, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->format = k;
        *formatSet = true;
        break;
    }
    case 7: ls->format = F_LONG; *formatSet = true; ls->fullTime = true; lsTimeStyle(ls, "full-iso"); break;
    case 8: ls->groupDirsFirst = true; break;
    case 9: ls->si = true; break;
    case 10: ls->deref = 'd'; break;
    case 11: {
        char **v = (char **)realloc(ls->hide, (ls->nHide + 1) * sizeof(char *));
        if (v) { ls->hide = v; ls->hide[ls->nHide++] = (char *)val; }
        break;
    }
    case 12: break;
    case 13: {
        static const char *const n[] = {"none", "slash", "file-type", "classify"};
        static const int v[] = {I_NONE, I_SLASH, I_FILE_TYPE, I_CLASSIFY};
        int k;
        if (!lsArgmatch("--indicator-style", val, n, v, 4, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->indicator = k;
        break;
    }
    case 14: ls->hideControl = false; *hideSet = true; break;
    case 15: {
        static const char *const n[] = {"literal", "shell", "shell-always", "shell-escape", "shell-escape-always",
                                        "c", "c-maybe", "escape", "locale", "clocale"};
        static const int v[] = {Q_LITERAL, Q_SHELL, Q_SHELL_ALWAYS, Q_SHELL_ESCAPE, Q_SHELL_ESCAPE_ALWAYS,
                                Q_C, Q_C_MAYBE, Q_ESCAPE, Q_LOCALE, Q_CLOCALE};
        int k;
        if (!lsArgmatch("--quoting-style", val, n, v, 10, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->quoting = k;
        *quotingSet = true;
        break;
    }
    case 16: {
        static const char *const n[] = {"none", "size", "time", "version", "extension", "name", "width"};
        static const int v[] = {S_NONE, S_SIZE, S_TIME, S_VERSION, S_EXT, S_NAME, S_WIDTH};
        int k;
        if (!lsArgmatch("--sort", val, n, v, 7, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->sort = k;
        break;
    }
    case 17: {
        static const char *const n[] = {"atime", "access", "use", "ctime", "status", "birth", "creation",
                                        "mtime", "modification"};
        static const int v[] = {'a', 'a', 'a', 'c', 'c', 'b', 'b', 'm', 'm'};
        int k;
        if (!lsArgmatch("--time", val, n, v, 9, &k)) { lsTry(); ls->status = 1; return 1; }
        ls->timeKind = (char)k;
        break;
    }
    case 18: if (!lsTimeStyle(ls, val)) { ls->status = lsTry(); return 1; } break;
    case 19: ls->zero = true; break;
    case 20: lsUsage(); ls->status = 0; return 1;
    case 21: puts("ls (SmallCLUE) 9.4"); ls->status = 0; return 1;
    default: break;
    }
    return 0;
}

int smallclueLsCommand(int argc, char **argv) {
    Ls *ls = (Ls *)calloc(1, sizeof(Ls));
    char **ops = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nops = 0, status = 2;
    if (!ls || !ops) { free(ls); free(ops); return 2; }
    bool tty = isatty(1);
    ls->format = tty ? F_COLUMNS : F_ONE;
    ls->quoting = tty ? Q_SHELL_ESCAPE : Q_LITERAL;
    ls->hideControl = tty;
    ls->showOwner = ls->showGroup = true;
    ls->timeKind = 'm';
    ls->blockSize = 1024;
    ls->sizeBlock = 1;
    ls->tabSize = 8;
    ls->timeRecent = "%b %e %H:%M";
    ls->timeOld = "%b %e  %Y";
    clock_gettime(CLOCK_REALTIME, &ls->now);
    bool formatSet = false, quotingSet = false, hideSet = false;
    const char *qs = getenv("QUOTING_STYLE");
    if (qs) {
        static const char *const n[] = {"literal", "shell", "shell-always", "shell-escape", "shell-escape-always",
                                        "c", "c-maybe", "escape", "locale", "clocale"};
        for (int i = 0; i < 10; i++) if (!strcmp(qs, n[i])) ls->quoting = i;
    }
    const char *ts = getenv("TIME_STYLE");
    if (ts && *ts && !lsTimeStyle(ls, ts)) { status = 2; goto done; }
    const char *bs = getenv("LS_BLOCK_SIZE");
    if (!bs) bs = getenv("BLOCK_SIZE");
    if (bs && *bs) lsBlockSize(ls, bs, true);
    if (getenv("POSIXLY_CORRECT") && !bs) ls->blockSize = 512;
    ls->lineLength = 80;
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) {
        long v = strtol(cols, NULL, 10);
        if (v > 0) ls->lineLength = (size_t)v;
    }
    if (tty) {
        struct winsize ws;
        if (ioctl(1, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) ls->lineLength = ws.ws_col;
    }
    const char *tabs = getenv("TABSIZE");
    if (tabs && *tabs) {
        char *end;
        long v = strtol(tabs, &end, 10);
        if (!*end && v >= 0) ls->tabSize = (int)v;
    }

    bool endOfOptions = false;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            ops[nops++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            const LsLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(lsLongs) / sizeof(lsLongs[0]); k++) {
                if (strncmp(lsLongs[k].name, opt, len)) continue;
                if (strlen(lsLongs[k].name) == len) { m = &lsLongs[k]; matches = 1; break; }
                if (m && m->c == lsLongs[k].c) continue;
                m = &lsLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "ls: option '%s' is ambiguous\n" : "ls: unrecognized option '%s'\n", arg);
                status = lsTry();
                goto done;
            }
            const char *val = NULL;
            if (eq) {
                if (m->arg == 0) {
                    fprintf(stderr, "ls: option '--%s' doesn't allow an argument\n", m->name);
                    status = lsTry();
                    goto done;
                }
                val = eq + 1;
            } else if (m->arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "ls: option '--%s' requires an argument\n", m->name);
                    status = lsTry();
                    goto done;
                }
                val = argv[++i];
            }
            if (lsOption(ls, m->c, val, &formatSet, &quotingSet, &hideSet)) { status = ls->status; goto done; }
            continue;
        }
        for (const char *p = arg + 1; *p; p++) {
            char c = *p;
            if (strchr("ITw", c)) {
                const char *val = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
                if (!val) {
                    fprintf(stderr, "ls: option requires an argument -- '%c'\n", c);
                    status = lsTry();
                    goto done;
                }
                if (lsOption(ls, c, val, &formatSet, &quotingSet, &hideSet)) { status = ls->status; goto done; }
                break;
            }
            if (!strchr("aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1", c)) {
                fprintf(stderr, "ls: invalid option -- '%c'\n", c);
                status = lsTry();
                goto done;
            }
            if (lsOption(ls, c, NULL, &formatSet, &quotingSet, &hideSet)) { status = ls->status; goto done; }
        }
    }
    /* -c/-u without -l sort by that time, as GNU does; -f turns off -l's
     * colour and long output only in old GNU, not 9. */
    if (ls->timeKind != 'm' && ls->format != F_LONG && ls->sort == S_NAME) ls->sort = S_TIME;
    if (ls->color) lsParseColors(ls);
    if (ls->deref == 0 && !ls->dirsAsFiles && ls->indicator != I_CLASSIFY && ls->format != F_LONG) ls->deref = 'd';

    LsFiles files = {NULL, 0, 0};
    if (nops == 0) ops[nops++] = (char *)".";
    for (int k = 0; k < nops; k++) {
        LsFile f;
        memset(&f, 0, sizeof(f));
        f.name = strdup(ops[k]);
        f.path = strdup(ops[k]);
        f.cmdline = true;
        bool follow = ls->deref == 'L' || ls->deref == 'H';
        if (!lsStat(ls, &f, follow, true)) {
            free(f.name);
            free(f.path);
            continue;
        }
        if (ls->deref == 'd' && S_ISLNK(f.st.st_mode) && f.linkOk && S_ISDIR(f.linkMode)) stat(f.path, &f.st);
        lsPush(&files, f);
    }
    ls->status = ls->status;
    lsSort(ls, &files);
    lsComputeWidths(ls, &files);
    LsFiles plain = {NULL, 0, 0}, dirs = {NULL, 0, 0};
    for (size_t k = 0; k < files.n; k++) {
        if (!ls->dirsAsFiles && lsIsDir(&files.v[k])) lsPush(&dirs, files.v[k]);
        else lsPush(&plain, files.v[k]);
    }
    if (plain.n) {
        lsPrintFiles(ls, &plain);
        ls->printedSomething = true;
    }
    bool headers = nops > 1 || ls->recursive;
    for (size_t k = 0; k < dirs.n; k++) lsDir(ls, dirs.v[k].name, dirs.v[k].path, true, headers);
    lsFreeFiles(&plain);
    lsFreeFiles(&dirs);
    free(plain.v);
    free(dirs.v);
    free(files.v);
    status = ls->status;

done:
    fflush(stdout);
    if (ferror(stdout) && status == 0) status = 2;
    free(ls->ignore);
    free(ls->hide);
    free(ls->colorBuf);
    free(ls->extPat);
    free(ls->extCode);
    free(ls);
    free(ops);
    return status;
}
