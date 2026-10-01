/*
 * find: search for files in a directory hierarchy, compatible with GNU
 * findutils 4.9.
 *
 * The find this replaces took one starting point, visited every directory's
 * contents before the directory itself (so `find .` printed `.` last), and
 * knew -name, -iname, -type, -mtime, -newer, -size, -print, -print0,
 * -delete and -exec ... ';' only. This is GNU's: any number of starting
 * points; -P, -H, -L and -follow; pre-order with -depth for post-order;
 * GNU's expression grammar (! -not -a -and -o -or , and parentheses) with
 * its error messages; the global options (-maxdepth, -mindepth, -depth,
 * -xdev/-mount, -daystart, -regextype, -ignore_readdir_race, -noleaf,
 * -warn/-nowarn); the tests (-name -iname -path -ipath -wholename
 * -iwholename -lname -ilname -regex -iregex -type -xtype -size -empty
 * -perm -user -group -uid -gid -nouser -nogroup -links -inum -samefile
 * -newer -anewer -cnewer -newerXY -[acm]time -[acm]min -used -readable
 * -writable -executable -fstype -true -false); and the actions (-print
 * -print0 -printf -fprint -fprint0 -fprintf -ls -fls -exec/-execdir with
 * ';' and '+', -ok/-okdir, -delete, -prune, -quit), with GNU's -printf
 * directives and -ls layout.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "find_app.h"
#include "app_hooks.h"
#include "gnu_util.h"
#include "spawn.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define FIND_ATIM(st) ((st)->st_atimespec)
#define FIND_MTIM(st) ((st)->st_mtimespec)
#define FIND_CTIM(st) ((st)->st_ctimespec)
#define FIND_BTIM(st) ((st)->st_birthtimespec)
#else
#define FIND_ATIM(st) ((st)->st_atim)
#define FIND_MTIM(st) ((st)->st_mtim)
#define FIND_CTIM(st) ((st)->st_ctim)
#define FIND_BTIM(st) ((st)->st_mtim)
#endif

#define FIND_DAY 86400.0
#define FIND_BATCH_MAX 131072

struct Find;
struct FindNode;

/* The file being considered. */
typedef struct {
    const char *path;      /* as printed */
    const char *real;      /* for system calls (the host may translate) */
    const char *start;     /* its starting point */
    int depth;
    struct stat st;
    bool statOk;
    int statErr;
} FindEntry;

typedef bool (*FindPred)(struct Find *, struct FindNode *, FindEntry *);

typedef struct {
    char *lit;             /* literal text before the directive */
    size_t litLen;
    char spec[32];         /* the flags/width/precision part, "%-10" */
    char conv;             /* directive letter; 0 for none */
    char sub;              /* A/C/T/B's second letter */
    bool stop;             /* \c: stop here */
} FindFmt;

typedef struct {
    char **paths;
    size_t n, cap, chars;
    char *dir;             /* -execdir: the directory the batch runs in */
} FindBatch;

typedef enum { FN_AND, FN_OR, FN_NOT, FN_COMMA, FN_PRED } FindKind;

typedef struct FindNode {
    FindKind kind;
    struct FindNode *l, *r;
    FindPred fn;
    const char *name;      /* the predicate as written, for messages */
    const char *s;
    int flags;
    char cmp;              /* '+', '-', or '=' */
    double num;
    uintmax_t unum;
    struct timespec ts;
    char which, refWhich;  /* time fields: 'a', 'c', 'm', 'B' */
    mode_t mode, dirMode;
    dev_t dev;
    ino_t ino;
    char types[16];
    regex_t re;
    bool reOk;
    char **argv;           /* -exec family: the command */
    int argc;
    bool plus, inDir, ask;
    bool action;           /* suppresses the default -print */
    double window;         /* time tests: the unit, for an exact match */
    FindBatch batch;
    FILE *out;
    bool nul;
    FindFmt *fmt;
    size_t nfmt;
    struct FindNode *nextExec;
} FindNode;

typedef struct {
    dev_t dev;
    ino_t ino;
    const char *path;
} FindAncestor;

typedef struct Find {
    char follow;           /* 'P', 'H' or 'L' */
    int maxDepth, minDepth;
    bool depthFirst, explicitDepth, xdev, daystart, ignoreRace, warn, hasDelete, hasPrune;
    int regexType;         /* REG_EXTENDED or 0, plus emacs translation */
    bool emacs;
    struct timespec now;
    struct timespec dayStart;  /* GNU's cur_day_start: now - 1 day, or midnight with -daystart */
    FindNode *root;
    int status;
    bool quit, prune;
    dev_t rootDev;
    FindAncestor *anc;
    size_t nanc, canc;
    FindNode *execs;       /* -exec ... + nodes, to flush */
    FILE **files;          /* -fprint etc. targets */
    char **fileNames;
    size_t nfiles;
    char **argv;
    int argc, pos;
    bool sawTest;          /* a non-option seen, for the positional warning */
    const char *lastTest;
    int lsInode, lsBlocks, lsLinks, lsUser, lsGroup, lsSize;
    char *mounts;          /* /proc/self/mounts, read once for -fstype/%F */
} Find;

static void findErr(Find *f, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("find: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    f->status = 1;
}

static const char *findQ(const char *s, char *buf, size_t n) {
    return gnuQuoteLocale(s, buf, n);
}

/* --- Stat according to -P/-H/-L. --- */

static bool findStat(Find *f, FindEntry *e) {
    bool follow = f->follow == 'L' || (f->follow == 'H' && e->depth == 0);
    int r = follow ? stat(e->real, &e->st) : lstat(e->real, &e->st);
    if (r != 0 && follow && (errno == ENOENT || errno == ELOOP))
        r = lstat(e->real, &e->st);   /* a dangling link is still a link */
    e->statOk = r == 0;
    e->statErr = r == 0 ? 0 : errno;
    return e->statOk;
}

static const char *findBase(const char *path, char *buf, size_t n) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && path[start - 1] != '/') start--;
    if (start == len && len > 0) start = len - 1;   /* "/" */
    snprintf(buf, n, "%.*s", (int)(len - start), path + start);
    return buf;
}

static char findTypeChar(mode_t m) {
    if (S_ISREG(m)) return 'f';
    if (S_ISDIR(m)) return 'd';
    if (S_ISLNK(m)) return 'l';
    if (S_ISBLK(m)) return 'b';
    if (S_ISCHR(m)) return 'c';
    if (S_ISFIFO(m)) return 'p';
    if (S_ISSOCK(m)) return 's';
    return 'U';
}

static struct timespec findTime(const struct stat *st, char which) {
    switch (which) {
    case 'a': return FIND_ATIM(st);
    case 'c': return FIND_CTIM(st);
    case 'B': return FIND_BTIM(st);
    default: return FIND_MTIM(st);
    }
}

static int findTsCmp(struct timespec a, struct timespec b) {
    if (a.tv_sec != b.tv_sec) return a.tv_sec < b.tv_sec ? -1 : 1;
    return (a.tv_nsec > b.tv_nsec) - (a.tv_nsec < b.tv_nsec);
}

static bool findCmpNum(char cmp, double actual, double want) {
    if (cmp == '+') return actual > want;
    if (cmp == '-') return actual < want;
    return actual == want;
}

/* --- Tests. --- */

static bool pTrue(Find *f, FindNode *n, FindEntry *e) { (void)f; (void)n; (void)e; return true; }
static bool pFalse(Find *f, FindNode *n, FindEntry *e) { (void)f; (void)n; (void)e; return false; }

static bool pName(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    char b[4096];
    return fnmatch(n->s, findBase(e->path, b, sizeof(b)), n->flags) == 0;
}

static bool pPath(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return fnmatch(n->s, e->path, n->flags) == 0;
}

static bool pLname(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    char target[4096];
    struct stat lst;
    if (lstat(e->real, &lst) != 0 || !S_ISLNK(lst.st_mode)) return false;
    ssize_t len = readlink(e->real, target, sizeof(target) - 1);
    if (len < 0) return false;
    target[len] = '\0';
    return fnmatch(n->s, target, n->flags) == 0;
}

static bool pRegex(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return n->reOk && regexec(&n->re, e->path, 0, NULL, 0) == 0;
}

static bool pType(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && strchr(n->types, findTypeChar(e->st.st_mode)) != NULL;
}

/* -xtype: the type the other way round -- of the target under -P, of the
 * link itself under -L. */
static bool pXtype(Find *f, FindNode *n, FindEntry *e) {
    struct stat st;
    int r;
    if (f->follow == 'L') r = lstat(e->real, &st);
    else if ((r = stat(e->real, &st)) != 0) r = lstat(e->real, &st);
    return r == 0 && strchr(n->types, findTypeChar(st.st_mode)) != NULL;
}

static bool pSize(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    if (!e->statOk) return false;
    uintmax_t size = (uintmax_t)e->st.st_size;
    uintmax_t units = (size + n->unum - 1) / n->unum;   /* rounded up, as GNU */
    return findCmpNum(n->cmp, (double)units, n->num);
}

static bool pEmpty(Find *f, FindNode *n, FindEntry *e) {
    (void)f; (void)n;
    if (!e->statOk) return false;
    if (S_ISREG(e->st.st_mode)) return e->st.st_size == 0;
    if (!S_ISDIR(e->st.st_mode)) return false;
    DIR *d = opendir(e->real);
    if (!d) return false;
    struct dirent *de;
    bool empty = true;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) { empty = false; break; }
    }
    closedir(d);
    return empty;
}

static bool pPerm(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    if (!e->statOk) return false;
    mode_t want = S_ISDIR(e->st.st_mode) ? n->dirMode : n->mode;
    mode_t have = e->st.st_mode & 07777;
    if (n->cmp == '-') return (have & want) == want;
    if (n->cmp == '/') return want == 0 || (have & want) != 0;
    return have == want;
}

static bool pAccess(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return access(e->real, n->flags) == 0;
}

static bool pUid(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findCmpNum(n->cmp, (double)e->st.st_uid, n->num);
}

static bool pGid(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findCmpNum(n->cmp, (double)e->st.st_gid, n->num);
}

static bool pNouser(Find *f, FindNode *n, FindEntry *e) {
    (void)f; (void)n;
    return e->statOk && getpwuid(e->st.st_uid) == NULL;
}

static bool pNogroup(Find *f, FindNode *n, FindEntry *e) {
    (void)f; (void)n;
    return e->statOk && getgrgid(e->st.st_gid) == NULL;
}

static bool pLinks(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findCmpNum(n->cmp, (double)e->st.st_nlink, n->num);
}

static bool pInum(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findCmpNum(n->cmp, (double)e->st.st_ino, n->num);
}

static bool pSamefile(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && e->st.st_dev == n->dev && e->st.st_ino == n->ino;
}

static bool pNewer(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findTsCmp(findTime(&e->st, n->which), n->ts) > 0;
}

/* GNU's pred_timewindow. The reference n->ts is fixed at parse time:
 * "+N" means before it, "-N" after it, and "N" within one unit after it. */
static bool findWindow(FindNode *n, struct timespec t) {
    if (n->cmp == '+') return findTsCmp(t, n->ts) < 0;
    if (n->cmp == '-') return findTsCmp(t, n->ts) > 0;
    double delta = (double)(t.tv_sec - n->ts.tv_sec) + (t.tv_nsec - n->ts.tv_nsec) / 1e9;
    return delta > 0.0 && delta <= n->window;
}

static bool pTime(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    return e->statOk && findWindow(n, findTime(&e->st, n->which));
}

/* -used: atime minus ctime, never true when the access came first. */
static bool pUsed(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    if (!e->statOk) return false;
    struct timespec a = FIND_ATIM(&e->st), c = FIND_CTIM(&e->st), d;
    if (findTsCmp(a, c) < 0) return false;
    d.tv_sec = a.tv_sec - c.tv_sec;
    d.tv_nsec = a.tv_nsec - c.tv_nsec;
    if (d.tv_nsec < 0) {
        d.tv_nsec += 1000000000;
        d.tv_sec -= 1;
    }
    return findWindow(n, d);
}

/* The mount a device number belongs to, from /proc/self/mounts. */
static void findFsType(Find *f, dev_t dev, char *out, size_t n) {
    snprintf(out, n, "unknown");
    if (!f->mounts) {
        FILE *fp = fopen("/proc/self/mounts", "r");
        if (!fp) return;
        size_t cap = 4096, len = 0;
        f->mounts = (char *)malloc(cap);
        size_t got;
        while (f->mounts && (got = fread(f->mounts + len, 1, cap - len - 1, fp)) > 0) {
            len += got;
            if (len + 1 == cap) {
                char *m = (char *)realloc(f->mounts, cap *= 2);
                if (!m) break;
                f->mounts = m;
            }
        }
        fclose(fp);
        if (!f->mounts) return;
        f->mounts[len] = '\0';
    }
    char *copy = strdup(f->mounts);
    if (!copy) return;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char src[1024], mnt[1024], type[128];
        if (sscanf(line, "%1023s %1023s %127s", src, mnt, type) != 3) continue;
        struct stat st;
        if (stat(mnt, &st) == 0 && st.st_dev == dev) snprintf(out, n, "%s", type);
    }
    free(copy);
}

static bool pFstype(Find *f, FindNode *n, FindEntry *e) {
    char type[128];
    if (!e->statOk) return false;
    findFsType(f, e->st.st_dev, type, sizeof(type));
    return strcmp(type, n->s) == 0;
}

/* --- Output. --- */

static void findModeString(mode_t m, char *out) {
    static const char rwx[] = "rwxrwxrwx";
    out[0] = findTypeChar(m) == 'f' ? '-' : findTypeChar(m) == 'U' ? '?' : findTypeChar(m);
    for (int i = 0; i < 9; i++) out[i + 1] = (m & (0400 >> i)) ? rwx[i] : '-';
    if (m & S_ISUID) out[3] = (m & 0100) ? 's' : 'S';
    if (m & S_ISGID) out[6] = (m & 0010) ? 's' : 'S';
    if (m & S_ISVTX) out[9] = (m & 0001) ? 't' : 'T';
    out[10] = '\0';
}

static bool pPrint(Find *f, FindNode *n, FindEntry *e) {
    (void)f;
    fputs(e->path, n->out);
    fputc(n->nul ? '\0' : '\n', n->out);
    return true;
}

static void findLsWidth(int *w, const char *s) {
    int len = (int)strlen(s);
    if (len > *w) *w = len;
}

static bool pLs(Find *f, FindNode *n, FindEntry *e) {
    if (!e->statOk) return true;
    char ino[32], blocks[32], links[32], size[48], user[64], group[64], mode[12], when[64];
    const struct stat *st = &e->st;
    snprintf(ino, sizeof(ino), "%ju", (uintmax_t)st->st_ino);
    snprintf(blocks, sizeof(blocks), "%ju", ((uintmax_t)st->st_blocks + 1) / 2);
    snprintf(links, sizeof(links), "%ju", (uintmax_t)st->st_nlink);
    if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode))
        snprintf(size, sizeof(size), "%u, %u", (unsigned)((st->st_rdev >> 8) & 0xfff),
                 (unsigned)((st->st_rdev & 0xff) | ((st->st_rdev >> 12) & 0xfff00)));
    else
        snprintf(size, sizeof(size), "%jd", (intmax_t)st->st_size);
    struct passwd *pw = getpwuid(st->st_uid);
    struct group *gr = getgrgid(st->st_gid);
    if (pw) snprintf(user, sizeof(user), "%s", pw->pw_name);
    else snprintf(user, sizeof(user), "%u", (unsigned)st->st_uid);
    if (gr) snprintf(group, sizeof(group), "%s", gr->gr_name);
    else snprintf(group, sizeof(group), "%u", (unsigned)st->st_gid);
    findModeString(st->st_mode, mode);
    struct timespec mt = FIND_MTIM(st);
    time_t t = mt.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    /* Recent (within six months, not in the future): the time; else the year. */
    double age = (double)f->now.tv_sec - (double)t;
    strftime(when, sizeof(when), age >= 0 && age < 31556952 / 2 ? "%b %e %H:%M" : "%b %e  %Y", &tm);
    findLsWidth(&f->lsInode, ino);
    findLsWidth(&f->lsBlocks, blocks);
    findLsWidth(&f->lsLinks, links);
    findLsWidth(&f->lsUser, user);
    findLsWidth(&f->lsGroup, group);
    findLsWidth(&f->lsSize, size);
    fprintf(n->out, "%*s %*s %s %*s %-*s %-*s %*s %s %s", f->lsInode, ino, f->lsBlocks, blocks, mode,
            f->lsLinks, links, f->lsUser, user, f->lsGroup, group, f->lsSize, size, when, e->path);
    if (S_ISLNK(st->st_mode)) {
        char target[4096];
        ssize_t len = readlink(e->real, target, sizeof(target) - 1);
        if (len >= 0) {
            target[len] = '\0';
            fprintf(n->out, " -> %s", target);
        }
    }
    fputc('\n', n->out);
    return true;
}

/* %t, %a, %c: ctime's layout with GNU's ten-digit fraction. */
static void findCtime(struct timespec ts, char *out, size_t n) {
    static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    time_t t = ts.tv_sec;
    struct tm tm;
    if (!localtime_r(&t, &tm)) {
        snprintf(out, n, "%jd", (intmax_t)t);
        return;
    }
    snprintf(out, n, "%3s %3s %2d %02d:%02d:%02d.%09ld0 %04d", days[tm.tm_wday], months[tm.tm_mon], tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (long)ts.tv_nsec, 1900 + tm.tm_year);
}

static void findDate(struct timespec ts, char kind, char *out, size_t n) {
    if (kind == '@') {
        snprintf(out, n, "%jd.%09ld0", (intmax_t)ts.tv_sec, (long)ts.tv_nsec);
        return;
    }
    char fmt[8] = {'%', kind, '\0'};
    if (kind == '+') strcpy(fmt, "%F+%T");
    if (!strchr("+aAbBcCdDeFgGhHIjklmMnprRsStTuUVwWxXyYzZ", kind)) {
        snprintf(out, n, "%%%c", kind);   /* glibc leaves an unknown one as is */
        return;
    }
    time_t t = ts.tv_sec;
    struct tm tm;
    if (!localtime_r(&t, &tm) || strftime(out, n, fmt, &tm) == 0) {
        out[0] = '\0';
        return;
    }
    if (kind == 'S' || kind == 'T' || kind == '+') {
        size_t len = strlen(out);
        snprintf(out + len, n - len, ".%09ld0", (long)ts.tv_nsec);
    }
}

/* One -printf directive, as a string padded per its flags and width. */
static void findEmit(FILE *out, const char *spec, const char *text) {
    const char *p = spec + 1;
    bool left = false;
    while (*p && strchr("-+ #0", *p)) {
        if (*p == '-') left = true;
        p++;
    }
    int width = 0, prec = -1;
    while (isdigit((unsigned char)*p)) width = width * 10 + (*p++ - '0');
    if (*p == '.') {
        p++;
        prec = 0;
        while (isdigit((unsigned char)*p)) prec = prec * 10 + (*p++ - '0');
    }
    int len = (int)strlen(text);
    if (prec >= 0 && prec < len) len = prec;
    if (!left) for (int i = len; i < width; i++) fputc(' ', out);
    fwrite(text, 1, (size_t)len, out);
    if (left) for (int i = len; i < width; i++) fputc(' ', out);
}

static bool pPrintf(Find *f, FindNode *n, FindEntry *e) {
    char buf[8192];
    const struct stat *st = &e->st;
    for (size_t i = 0; i < n->nfmt; i++) {
        FindFmt *d = &n->fmt[i];
        fwrite(d->lit, 1, d->litLen, n->out);
        if (d->stop) break;
        if (!d->conv) continue;
        buf[0] = '\0';
        switch (d->conv) {
        case 'p': snprintf(buf, sizeof(buf), "%s", e->path); break;
        case 'f': findBase(e->path, buf, sizeof(buf)); break;
        case 'h': {
            const char *slash = strrchr(e->path, '/');
            if (!slash) snprintf(buf, sizeof(buf), ".");
            else if (slash == e->path) snprintf(buf, sizeof(buf), "/");
            else snprintf(buf, sizeof(buf), "%.*s", (int)(slash - e->path), e->path);
            break;
        }
        case 'P': {
            size_t sl = strlen(e->start);
            const char *rest = e->path + (strncmp(e->path, e->start, sl) ? 0 : sl);
            while (*rest == '/' && e->depth > 0) rest++;
            snprintf(buf, sizeof(buf), "%s", e->depth == 0 ? "" : rest);
            break;
        }
        case 'H': snprintf(buf, sizeof(buf), "%s", e->start); break;
        case 'd': snprintf(buf, sizeof(buf), "%d", e->depth); break;
        case 'D': snprintf(buf, sizeof(buf), "%ju", (uintmax_t)st->st_dev); break;
        case 'i': snprintf(buf, sizeof(buf), "%ju", (uintmax_t)st->st_ino); break;
        case 'n': snprintf(buf, sizeof(buf), "%ju", (uintmax_t)st->st_nlink); break;
        case 's': snprintf(buf, sizeof(buf), "%jd", (intmax_t)st->st_size); break;
        case 'b': snprintf(buf, sizeof(buf), "%ju", (uintmax_t)st->st_blocks); break;
        case 'k': snprintf(buf, sizeof(buf), "%ju", ((uintmax_t)st->st_blocks + 1) / 2); break;
        case 'm': snprintf(buf, sizeof(buf), "%o", (unsigned)(st->st_mode & 07777)); break;
        case 'M': findModeString(st->st_mode, buf); break;
        case 'U': snprintf(buf, sizeof(buf), "%u", (unsigned)st->st_uid); break;
        case 'G': snprintf(buf, sizeof(buf), "%u", (unsigned)st->st_gid); break;
        case 'u': {
            struct passwd *pw = getpwuid(st->st_uid);
            if (pw) snprintf(buf, sizeof(buf), "%s", pw->pw_name);
            else snprintf(buf, sizeof(buf), "%u", (unsigned)st->st_uid);
            break;
        }
        case 'g': {
            struct group *gr = getgrgid(st->st_gid);
            if (gr) snprintf(buf, sizeof(buf), "%s", gr->gr_name);
            else snprintf(buf, sizeof(buf), "%u", (unsigned)st->st_gid);
            break;
        }
        case 'l':
            if (S_ISLNK(st->st_mode)) {
                ssize_t len = readlink(e->real, buf, sizeof(buf) - 1);
                buf[len < 0 ? 0 : len] = '\0';
            }
            break;
        case 'y': buf[0] = findTypeChar(st->st_mode); buf[1] = '\0'; break;
        case 'Y': {
            struct stat t;
            if (!S_ISLNK(st->st_mode)) buf[0] = findTypeChar(st->st_mode);
            else if (stat(e->real, &t) == 0) buf[0] = findTypeChar(t.st_mode);
            else buf[0] = errno == ELOOP ? 'L' : errno == ENOENT ? 'N' : '?';
            buf[1] = '\0';
            break;
        }
        case 'F': findFsType(f, st->st_dev, buf, sizeof(buf)); break;
        case 'S':
            snprintf(buf, sizeof(buf), "%g",
                     st->st_size ? (double)st->st_blocks * 512.0 / (double)st->st_size : 1.0);
            break;
        case 'Z': break;
        case 'a': findCtime(FIND_ATIM(st), buf, sizeof(buf)); break;
        case 'c': findCtime(FIND_CTIM(st), buf, sizeof(buf)); break;
        case 't': findCtime(FIND_MTIM(st), buf, sizeof(buf)); break;
        case 'A': findDate(FIND_ATIM(st), d->sub, buf, sizeof(buf)); break;
        case 'B': findDate(FIND_BTIM(st), d->sub, buf, sizeof(buf)); break;
        case 'C': findDate(FIND_CTIM(st), d->sub, buf, sizeof(buf)); break;
        case 'T': findDate(FIND_MTIM(st), d->sub, buf, sizeof(buf)); break;
        case '%': snprintf(buf, sizeof(buf), "%%"); break;
        default: break;
        }
        findEmit(n->out, d->spec, buf);
    }
    return true;
}

/* --- Running commands. --- */

static int findWait(pid_t pid) {
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return st;
}

/* Runs argv (in `dir` when set); true when it exited 0. */
static bool findRun(Find *f, char **argv, const char *dir) {
    fflush(stdout);
    int saved = -1;
    if (dir) {
        saved = open(".", O_RDONLY);
        if (chdir(dir) != 0) {
            char q[4096];
            findErr(f, "%s: %s", findQ(dir, q, sizeof(q)), strerror(errno));
            if (saved >= 0) close(saved);
            return false;
        }
    }
    int st = 0;
    int argcount = 0;
    while (argv[argcount]) argcount++;
    bool ran = smallclueAppRunInProcess(argcount, argv, &st);
    if (!ran) {
        pid_t pid = smallclueSpawnSimple(argv[0], argv, 1);
        if (pid < 0) {
            /* GNU's child reports it and fails; find's status is unchanged. */
            char q[4096];
            fprintf(stderr, "find: %s: %s\n", findQ(argv[0], q, sizeof(q)), strerror(errno));
            st = -1;
        } else {
            st = findWait(pid);
            st = st >= 0 && WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        }
    }
    if (saved >= 0) {
        if (fchdir(saved) != 0) {}
        close(saved);
    }
    return st == 0;
}

static char *findReplace(const char *arg, const char *path) {
    const char *m = strstr(arg, "{}");
    if (!m) return strdup(arg);
    size_t pl = strlen(path), n = 0;
    for (const char *p = arg; (p = strstr(p, "{}")); p += 2) n++;
    char *out = (char *)malloc(strlen(arg) + n * pl + 1), *o = out;
    if (!out) return NULL;
    for (const char *p = arg;;) {
        const char *q = strstr(p, "{}");
        size_t k = q ? (size_t)(q - p) : strlen(p);
        memcpy(o, p, k);
        o += k;
        if (!q) break;
        memcpy(o, path, pl);
        o += pl;
        p = q + 2;
    }
    *o = '\0';
    return out;
}

/* -execdir's view: the directory, and "./name". */
static void findSplitDir(const FindEntry *e, char **dir, char **name) {
    char b[4096];
    findBase(e->real, b, sizeof(b));
    const char *slash = strrchr(e->real, '/');
    size_t dl = slash ? (size_t)(slash - e->real) : 0;
    while (slash && dl > 0 && e->real[dl - 1] == '/') dl--;
    if (!slash) *dir = strdup(".");
    else if (slash == e->real || dl == 0) *dir = strdup("/");
    else *dir = strndup(e->real, dl);
    size_t len = strlen(b) + 3;
    *name = (char *)malloc(len);
    if (*name) snprintf(*name, len, strcmp(b, "/") ? "./%s" : "%s", b);
}

static bool findFlush(Find *f, FindNode *n) {
    FindBatch *b = &n->batch;
    if (b->n == 0) return true;
    int total = n->argc - 1 + (int)b->n;
    char **argv = (char **)calloc((size_t)total + 1, sizeof(char *));
    if (!argv) return false;
    int k = 0;
    for (int i = 0; i < n->argc - 1; i++) argv[k++] = n->argv[i];
    for (size_t i = 0; i < b->n; i++) argv[k++] = b->paths[i];
    argv[k] = NULL;
    bool ok = findRun(f, argv, b->dir);
    if (!ok) f->status = 1;
    free(argv);
    for (size_t i = 0; i < b->n; i++) free(b->paths[i]);
    b->n = 0;
    b->chars = 0;
    free(b->dir);
    b->dir = NULL;
    return ok;
}

static bool pExec(Find *f, FindNode *n, FindEntry *e) {
    char *dir = NULL, *name = NULL;
    const char *subst = e->path;
    if (n->inDir) {
        findSplitDir(e, &dir, &name);
        subst = name;
    }
    if (n->plus) {
        FindBatch *b = &n->batch;
        if (n->inDir && b->dir && strcmp(b->dir, dir)) findFlush(f, n);
        size_t len = strlen(subst) + 1;
        if (b->n && b->chars + len > FIND_BATCH_MAX) findFlush(f, n);
        if (b->n == b->cap) {
            size_t cap = b->cap ? b->cap * 2 : 64;
            char **v = (char **)realloc(b->paths, cap * sizeof(char *));
            if (!v) { free(dir); free(name); return true; }
            b->paths = v;
            b->cap = cap;
        }
        b->paths[b->n++] = strdup(subst);
        b->chars += len;
        if (n->inDir && !b->dir) b->dir = dir;
        else free(dir);
        free(name);
        return true;
    }
    char **argv = (char **)calloc((size_t)n->argc + 1, sizeof(char *));
    bool ok = false;
    if (argv) {
        for (int i = 0; i < n->argc; i++) argv[i] = findReplace(n->argv[i], subst);
        bool go = true;
        if (n->ask) {
            fprintf(stderr, "< %s ... %s > ? ", argv[0], subst);
            fflush(stderr);
            char line[256];
            go = fgets(line, sizeof(line), stdin) && (line[0] == 'y' || line[0] == 'Y');
        }
        if (go) ok = findRun(f, argv, dir);
        for (int i = 0; i < n->argc; i++) free(argv[i]);
        free(argv);
    }
    free(dir);
    free(name);
    return ok;
}

static bool pDelete(Find *f, FindNode *n, FindEntry *e) {
    (void)n;
    char q[4096];
    if (!strcmp(e->path, ".")) return true;
    int r = e->statOk && S_ISDIR(e->st.st_mode) ? rmdir(e->real) : unlink(e->real);
    if (r != 0) {
        findErr(f, "cannot delete %s: %s", findQ(e->path, q, sizeof(q)), strerror(errno));
        return false;
    }
    return true;
}

static bool pPrune(Find *f, FindNode *n, FindEntry *e) {
    (void)n; (void)e;
    if (!f->depthFirst) f->prune = true;
    return true;
}

static bool pQuit(Find *f, FindNode *n, FindEntry *e) {
    (void)n; (void)e;
    f->quit = true;
    return true;
}

/* --- Evaluation and the walk. --- */

static bool findEval(Find *f, FindNode *n, FindEntry *e) {
    switch (n->kind) {
    case FN_AND: return findEval(f, n->l, e) && !f->quit && findEval(f, n->r, e);
    case FN_OR: return findEval(f, n->l, e) || (!f->quit && findEval(f, n->r, e));
    case FN_NOT: return !findEval(f, n->l, e);
    case FN_COMMA: findEval(f, n->l, e); return f->quit ? false : findEval(f, n->r, e);
    default: return n->fn(f, n, e);
    }
}

static char *findJoin(const char *dir, const char *name) {
    size_t dl = strlen(dir), nl = strlen(name);
    char *p = (char *)malloc(dl + nl + 2);
    if (!p) return NULL;
    memcpy(p, dir, dl);
    if (dl == 0 || dir[dl - 1] != '/') p[dl++] = '/';
    memcpy(p + dl, name, nl + 1);
    return p;
}

static void findVisit(Find *f, const char *path, const char *real, const char *start, int depth) {
    char q[4096], q2[4096];
    FindEntry e;
    memset(&e, 0, sizeof(e));
    e.path = path;
    e.real = real;
    e.start = start;
    e.depth = depth;
    if (!findStat(f, &e)) {
        if (!(f->ignoreRace && depth > 0 && e.statErr == ENOENT))
            findErr(f, "%s: %s", findQ(path, q, sizeof(q)), strerror(e.statErr));
        return;
    }
    if (depth == 0) f->rootDev = e.st.st_dev;
    bool isDir = S_ISDIR(e.st.st_mode);
    bool descend = isDir && (f->maxDepth < 0 || depth < f->maxDepth) && !(f->xdev && e.st.st_dev != f->rootDev);

    /* -L: a directory that is its own ancestor is a loop. */
    if (isDir && f->follow != 'P') {
        for (size_t i = 0; i < f->nanc; i++) {
            if (f->anc[i].dev == e.st.st_dev && f->anc[i].ino == e.st.st_ino) {
                findErr(f, "File system loop detected; %s is part of the same file system loop as %s.",
                        findQ(path, q, sizeof(q)), findQ(f->anc[i].path, q2, sizeof(q2)));
                return;
            }
        }
    }

    f->prune = false;
    if (!f->depthFirst && depth >= f->minDepth) findEval(f, f->root, &e);
    if (f->quit) return;
    if (f->prune) descend = false;

    if (descend) {
        DIR *d = opendir(real);
        if (!d) {
            findErr(f, "%s: %s", findQ(path, q, sizeof(q)), strerror(errno));
        } else {
            char **names = NULL;
            size_t n = 0, cap = 0;
            struct dirent *de;
            while ((de = readdir(d))) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                if (n == cap) {
                    cap = cap ? cap * 2 : 32;
                    char **v = (char **)realloc(names, cap * sizeof(char *));
                    if (!v) break;
                    names = v;
                }
                names[n++] = strdup(de->d_name);
            }
            closedir(d);
            if (f->nanc == f->canc) {
                f->canc = f->canc ? f->canc * 2 : 16;
                f->anc = (FindAncestor *)realloc(f->anc, f->canc * sizeof(FindAncestor));
            }
            if (f->anc) {
                f->anc[f->nanc].dev = e.st.st_dev;
                f->anc[f->nanc].ino = e.st.st_ino;
                f->anc[f->nanc].path = path;
                f->nanc++;
            }
            for (size_t i = 0; i < n && !f->quit; i++) {
                char *cp = findJoin(path, names[i]);
                char *cr = real == path ? cp : findJoin(real, names[i]);
                if (cp && cr) findVisit(f, cp, cr, start, depth + 1);
                if (cr != cp) free(cr);
                free(cp);
            }
            if (f->anc && f->nanc) f->nanc--;
            for (size_t i = 0; i < n; i++) free(names[i]);
            free(names);
        }
    }
    if (f->quit) return;
    if (f->depthFirst && depth >= f->minDepth) {
        /* The directory's own stat may have changed (-delete emptied it). */
        findEval(f, f->root, &e);
    }
}

/* --- Parsing. --- */

static FindNode *findNew(FindKind kind) {
    FindNode *n = (FindNode *)calloc(1, sizeof(FindNode));
    if (n) n->kind = kind;
    return n;
}

static void findFree(FindNode *n) {
    if (!n) return;
    findFree(n->l);
    findFree(n->r);
    if (n->reOk) regfree(&n->re);
    for (size_t i = 0; i < n->nfmt; i++) free(n->fmt[i].lit);
    free(n->fmt);
    for (size_t i = 0; i < n->batch.n; i++) free(n->batch.paths[i]);
    free(n->batch.paths);
    free(n->batch.dir);
    free(n);
}

/* [+-]N: '+' more, '-' less, else exactly. */
static bool findNumArg(const char *s, char *cmp, double *num, bool allowFraction) {
    *cmp = '=';
    if (*s == '+' || *s == '-') *cmp = *s++;
    if (!isdigit((unsigned char)*s) && !(allowFraction && *s == '.')) return false;
    char *end;
    *num = allowFraction ? strtod(s, &end) : (double)strtoumax(s, &end, 10);
    return *end == '\0';
}

/* chmod-style symbolic modes, applied to 0 with no umask, for -perm. */
static bool findSymbolicMode(const char *s, mode_t *fileMode, mode_t *dirMode) {
    mode_t fm = 0, dm = 0;
    const char *p = s;
    for (;;) {
        mode_t who = 0;
        for (; *p && strchr("ugoa", *p); p++)
            who |= *p == 'u' ? 04700 : *p == 'g' ? 02070 : *p == 'o' ? 01007 : 07777;
        if (!who) who = 07777;
        if (!*p || !strchr("+-=", *p)) return false;
        while (*p && strchr("+-=", *p)) {
            char op = *p++;
            mode_t fbits = 0, dbits = 0;
            for (; *p && strchr("rwxXstugo", *p); p++) {
                switch (*p) {
                case 'r': fbits |= 0444; dbits |= 0444; break;
                case 'w': fbits |= 0222; dbits |= 0222; break;
                case 'x': fbits |= 0111; dbits |= 0111; break;
                case 'X': dbits |= 0111; if (fm & 0111) fbits |= 0111; break;
                case 's': fbits |= 06000; dbits |= 06000; break;
                case 't': fbits |= 01000; dbits |= 01000; break;
                case 'u': fbits |= (fm & 0700) ? ((fm & 0700) >> 6) * 0111 : 0;
                          dbits |= (dm & 0700) ? ((dm & 0700) >> 6) * 0111 : 0; break;
                case 'g': fbits |= ((fm & 070) >> 3) * 0111; dbits |= ((dm & 070) >> 3) * 0111; break;
                case 'o': fbits |= (fm & 07) * 0111; dbits |= (dm & 07) * 0111; break;
                }
            }
            fbits &= who;
            dbits &= who;
            if (op == '+') { fm |= fbits; dm |= dbits; }
            else if (op == '-') { fm &= ~fbits; dm &= ~dbits; }
            else { fm = (fm & ~(who & 07777)) | fbits; dm = (dm & ~(who & 07777)) | dbits; }
        }
        if (*p == ',') { p++; continue; }
        if (*p) return false;
        break;
    }
    *fileMode = fm;
    *dirMode = dm;
    return true;
}

static bool findTypes(Find *f, const char *arg, char *out) {
    size_t n = 0;
    for (const char *p = arg; *p; p++) {
        if (!strchr("bcdpflsD", *p)) {
            findErr(f, "Unknown argument to %s: %c", "-type", *p);
            return false;
        }
        if (n < 15) out[n++] = *p;
        if (p[1] == '\0') break;
        if (p[1] != ',') {
            findErr(f, "Must separate multiple arguments to -type using: ','");
            return false;
        }
        p++;
        if (p[1] == '\0') {
            findErr(f, "Last file type in list argument to -type is missing, i.e., list is ending on: ','");
            return false;
        }
    }
    if (n == 0) {
        findErr(f, "Arguments to -type should contain at least one letter");
        return false;
    }
    out[n] = '\0';
    return true;
}

/* find's regex dialects as POSIX extended, which every libc compiles the
 * same way. Emacs (the default) and the basic dialects write grouping and
 * alternation with a backslash; emacs has + and ? bare and no intervals;
 * GNU's basic syntax adds \+ and \?. A '*' that starts an expression, and
 * '^' or '$' away from its edges, are literal in both. */
static char *findToEre(const char *s, char dialect) {
    size_t len = strlen(s);
    char *out = (char *)malloc(len * 2 + 3), *o = out;
    if (!out) return NULL;
    bool atStart = true;
    for (const char *p = s; *p; p++) {
        if (*p == '[') {
            /* A bracket expression is the same in every dialect. */
            const char *q = p + 1;
            if (*q == '^') q++;
            if (*q == ']') q++;
            while (*q && *q != ']') {
                if (*q == '[' && (q[1] == ':' || q[1] == '.' || q[1] == '=')) {
                    const char *close = strchr(q + 2, q[1]);
                    q = close && close[1] == ']' ? close + 2 : q + 1;
                } else {
                    q++;
                }
            }
            if (*q == ']') q++;
            memcpy(o, p, (size_t)(q - p));
            o += q - p;
            p = q - 1;
            atStart = false;
            continue;
        }
        if (*p == '\\' && p[1]) {
            char c = *++p;
            if (c == '(' || c == '|') { *o++ = c; atStart = true; continue; }
            if (c == ')') { *o++ = c; atStart = false; continue; }
            if (dialect == 'b' && strchr("{}+?", c)) { *o++ = c; atStart = false; continue; }
            *o++ = '\\';
            *o++ = c;
            atStart = false;
            continue;
        }
        char c = *p;
        if (strchr("(){}|", c) || (dialect == 'b' && (c == '+' || c == '?')) || (c == '*' && atStart) ||
            (c == '^' && !atStart) ||
            (c == '$' && p[1] && !(p[1] == '\\' && (p[2] == ')' || p[2] == '|')))) {
            *o++ = '\\';
            *o++ = c;
        } else {
            *o++ = c;
        }
        atStart = c == '^' && atStart;
    }
    *o = '\0';
    return out;
}

/* glibc's messages, which GNU find prints. */
static const char *findRegexMessage(int code) {
    switch (code) {
    case REG_EPAREN: return "Unmatched ( or \\(";
    case REG_EBRACK: return "Unmatched [, [^, [:, [., or [=";
    case REG_EBRACE: return "Unmatched \\{";
    case REG_BADBR: return "Invalid content of \\{\\}";
    case REG_BADRPT: return "Invalid preceding regular expression";
    case REG_EESCAPE: return "Trailing backslash";
    case REG_ERANGE: return "Invalid range end";
    case REG_ECTYPE: return "Invalid character class name";
    case REG_ESUBREG: return "Invalid back reference";
    case REG_ECOLLATE: return "Invalid collation character";
    case REG_ESPACE: return "Memory exhausted";
    default: return "Invalid regular expression";
    }
}

static bool findCompileRegex(Find *f, FindNode *n, const char *pat, bool icase) {
    bool ere = !f->emacs && (f->regexType & REG_EXTENDED);
    char *src = ere ? strdup(pat) : findToEre(pat, f->emacs ? 'e' : 'b');
    if (!src) return false;
    size_t len = strlen(src) + 8;
    char *anchored = (char *)malloc(len);
    if (!anchored) { free(src); return false; }
    snprintf(anchored, len, "^(%s)$", src);
    int r = regcomp(&n->re, anchored, REG_EXTENDED | (icase ? REG_ICASE : 0) | REG_NOSUB);
    free(anchored);
    free(src);
    if (r != 0) {
        findErr(f, "failed to compile regular expression '%s': %s", pat, findRegexMessage(r));
        return false;
    }
    n->reOk = true;
    return true;
}

static FILE *findOpenOut(Find *f, const char *name) {
    char q[4096];
    if (!strcmp(name, "/dev/stdout")) return stdout;
    if (!strcmp(name, "/dev/stderr")) return stderr;
    for (size_t i = 0; i < f->nfiles; i++)
        if (!strcmp(f->fileNames[i], name)) return f->files[i];
    FILE *fp = fopen(name, "w");
    if (!fp) {
        findErr(f, "%s: %s", findQ(name, q, sizeof(q)), strerror(errno));
        return NULL;
    }
    FILE **nf = (FILE **)realloc(f->files, (f->nfiles + 1) * sizeof(FILE *));
    char **nn = (char **)realloc(f->fileNames, (f->nfiles + 1) * sizeof(char *));
    if (nf) f->files = nf;
    if (nn) f->fileNames = nn;
    if (!nf || !nn) { fclose(fp); return NULL; }
    f->files[f->nfiles] = fp;
    f->fileNames[f->nfiles] = strdup(name);
    f->nfiles++;
    return fp;
}

static bool findParseFormat(Find *f, FindNode *n, const char *s) {
    size_t cap = 8;
    n->fmt = (FindFmt *)calloc(cap, sizeof(FindFmt));
    if (!n->fmt) return false;
    char *lit = (char *)malloc(strlen(s) + 1);
    size_t ll = 0;
    if (!lit) return false;
    const char *p = s;
    for (;;) {
        FindFmt d;
        memset(&d, 0, sizeof(d));
        bool end = false;
        while (*p && !end) {
            if (*p == '\\') {
                p++;
                static const char esc[] = "a\ab\bf\fn\nr\rt\tv\v\\\\";
                const char *e = *p ? strchr(esc, *p) : NULL;
                if (e && (e - esc) % 2 == 0) { lit[ll++] = e[1]; p++; }
                else if (*p == 'c') { d.stop = true; p++; end = true; }
                else if (*p >= '0' && *p <= '7') {
                    int v = 0, k = 0;
                    while (k < 3 && *p >= '0' && *p <= '7') { v = v * 8 + (*p++ - '0'); k++; }
                    lit[ll++] = (char)v;
                } else if (*p == '\0') {
                    lit[ll++] = '\\';
                } else {
                    fprintf(stderr, "find: warning: unrecognized escape `\\%c'\n", *p);
                    lit[ll++] = '\\';
                    lit[ll++] = *p++;
                }
            } else if (*p == '%') {
                const char *q = p + 1;
                if (*q == '%') { lit[ll++] = '%'; p += 2; continue; }
                while (*q && strchr("-+ #0", *q)) q++;
                while (isdigit((unsigned char)*q)) q++;
                if (*q == '.') { q++; while (isdigit((unsigned char)*q)) q++; }
                if (*q && strchr("aAbBcCdDfFgGhHiklmMnpPsStTuUyYZ", *q)) {
                    size_t sl = (size_t)(q - p);
                    if (sl >= sizeof(d.spec)) sl = sizeof(d.spec) - 1;
                    memcpy(d.spec, p, sl);
                    d.spec[sl] = '\0';
                    d.conv = *q;
                    p = q + 1;
                    if (strchr("ABCT", d.conv)) {
                        if (!*p) {
                            findErr(f, "error: missing time format directive after %%%c", d.conv);
                            free(lit);
                            return false;
                        }
                        d.sub = *p++;
                    }
                    end = true;
                } else if (*q == '\0') {
                    findErr(f, "error: %s at end of format string", "%");
                    free(lit);
                    return false;
                } else {
                    fprintf(stderr, "find: warning: unrecognized format directive `%%%c'\n", *q);
                    memcpy(lit + ll, p, (size_t)(q - p) + 1);
                    ll += (size_t)(q - p) + 1;
                    p = q + 1;
                }
            } else {
                lit[ll++] = *p++;
            }
        }
        if (n->nfmt == cap) {
            FindFmt *v = (FindFmt *)realloc(n->fmt, (cap *= 2) * sizeof(FindFmt));
            if (!v) { free(lit); return false; }
            n->fmt = v;
        }
        d.lit = (char *)malloc(ll + 1);
        if (d.lit) memcpy(d.lit, lit, ll);
        d.litLen = ll;
        n->fmt[n->nfmt++] = d;
        ll = 0;
        if (!*p || d.stop) break;
    }
    free(lit);
    return true;
}

static FindNode *findParseComma(Find *f);

static const char *findNext(Find *f) {
    return f->pos < f->argc ? f->argv[f->pos] : NULL;
}

static const char *findArg(Find *f, const char *pred) {
    if (f->pos >= f->argc) {
        findErr(f, "missing argument to `%s'", pred);
        return NULL;
    }
    return f->argv[f->pos++];
}

static bool findUserId(const char *s, uid_t *out) {
    struct passwd *pw = getpwnam(s);
    if (pw) { *out = pw->pw_uid; return true; }
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (*s && *end == '\0') { *out = (uid_t)v; return true; }
    return false;
}

static bool findGroupId(const char *s, gid_t *out) {
    struct group *gr = getgrnam(s);
    if (gr) { *out = gr->gr_gid; return true; }
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (*s && *end == '\0') { *out = (gid_t)v; return true; }
    return false;
}

static bool findRefStat(Find *f, const char *path, struct stat *st) {
    char q[4096];
    int r = f->follow == 'P' ? lstat(path, st) : stat(path, st);
    if (r != 0) {
        findErr(f, "%s: %s", findQ(path, q, sizeof(q)), strerror(errno));
        return false;
    }
    return true;
}

/* GNU warns (when warnings are on: stdin a terminal, or -warn) about a
 * global option placed after a test. */
static void findPositional(Find *f, const char *opt) {
    if (f->sawTest && f->warn) {
        fprintf(stderr, "find: warning: you have specified the global option %s after the argument %s, but global "
                        "options are not positional, i.e., %s affects tests specified before it as well as those "
                        "specified after it.  Please specify global options before other arguments.\n",
                opt, f->lastTest, opt);
    }
}

/* One predicate, option or action; NULL after a message. */
static FindNode *findParsePrimary(Find *f) {
    char q[4096];
    const char *tok = findNext(f);
    if (!tok) {
        findErr(f, "invalid expression");
        return NULL;
    }
    if (!strcmp(tok, "(")) {
        f->pos++;
        const char *nx = findNext(f);
        if (nx && !strcmp(nx, ")")) {
            findErr(f, "invalid expression; empty parentheses are not allowed.");
            return NULL;
        }
        FindNode *n = findParseComma(f);
        if (!n) return NULL;
        nx = findNext(f);
        if (!nx || strcmp(nx, ")")) {
            findErr(f, "invalid expression; I was expecting to find a ')' somewhere but did not see one.");
            findFree(n);
            return NULL;
        }
        f->pos++;
        return n;
    }
    if (!strcmp(tok, ")")) {
        findErr(f, "you have too many ')'");
        return NULL;
    }
    if (tok[0] != '-' || tok[1] == '\0') {
        findErr(f, "paths must precede expression: `%s'", tok);
        if (f->pos > 0 && f->argv[f->pos - 1][0] == '-' && strstr("-name -iname -path -ipath -wholename -iwholename -lname -ilname", f->argv[f->pos - 1]))
            findErr(f, "possible unquoted pattern after predicate `%s'?", f->argv[f->pos - 1]);
        return NULL;
    }
    f->pos++;
    FindNode *n = findNew(FN_PRED);
    if (!n) return NULL;
    n->name = tok;
    n->fn = pTrue;
    const char *a;
    bool test = true;
#define NEED() do { if (!(a = findArg(f, tok))) goto fail; } while (0)
    if (!strcmp(tok, "-true")) {
    } else if (!strcmp(tok, "-false")) {
        n->fn = pFalse;
    } else if (!strcmp(tok, "-name") || !strcmp(tok, "-iname")) {
        NEED();
        n->s = a;
        n->flags = tok[1] == 'i' ? FNM_CASEFOLD : 0;
        n->fn = pName;
    } else if (!strcmp(tok, "-path") || !strcmp(tok, "-ipath") || !strcmp(tok, "-wholename") ||
               !strcmp(tok, "-iwholename")) {
        NEED();
        n->s = a;
        n->flags = tok[1] == 'i' ? FNM_CASEFOLD : 0;
        n->fn = pPath;
    } else if (!strcmp(tok, "-lname") || !strcmp(tok, "-ilname")) {
        NEED();
        n->s = a;
        n->flags = tok[1] == 'i' ? FNM_CASEFOLD : 0;
        n->fn = pLname;
    } else if (!strcmp(tok, "-regex") || !strcmp(tok, "-iregex")) {
        NEED();
        if (!findCompileRegex(f, n, a, tok[1] == 'i')) goto fail;
        n->fn = pRegex;
    } else if (!strcmp(tok, "-type") || !strcmp(tok, "-xtype")) {
        NEED();
        if (!findTypes(f, a, n->types)) goto fail;
        n->fn = tok[1] == 'x' ? pXtype : pType;
    } else if (!strcmp(tok, "-size")) {
        NEED();
        const char *p = a;
        n->cmp = '=';
        if (*p == '+' || *p == '-') n->cmp = *p++;
        char *end;
        if (!isdigit((unsigned char)*p)) {
            findErr(f, "Invalid argument `%s' to -size", a);
            goto fail;
        }
        n->num = (double)strtoumax(p, &end, 10);
        n->unum = 512;
        if (*end) {
            switch (*end) {
            case 'b': n->unum = 512; break;
            case 'c': n->unum = 1; break;
            case 'w': n->unum = 2; break;
            case 'k': n->unum = 1024; break;
            case 'M': n->unum = 1048576; break;
            case 'G': n->unum = 1073741824; break;
            default:
                findErr(f, "invalid -size type `%c'", *end);
                goto fail;
            }
            if (end[1]) {
                findErr(f, "invalid -size type `%s'", end);
                goto fail;
            }
        }
        n->fn = pSize;
    } else if (!strcmp(tok, "-empty")) {
        n->fn = pEmpty;
    } else if (!strcmp(tok, "-perm")) {
        NEED();
        const char *p = a;
        n->cmp = '=';
        if (*p == '-' || *p == '/') n->cmp = *p++;
        if (*p >= '0' && *p <= '7') {
            char *end;
            unsigned long v = strtoul(p, &end, 8);
            if (*end || v > 07777) {
                findErr(f, "invalid mode %s", findQ(a, q, sizeof(q)));
                goto fail;
            }
            n->mode = n->dirMode = (mode_t)v;
        } else if (!findSymbolicMode(p, &n->mode, &n->dirMode)) {
            findErr(f, "invalid mode %s", findQ(a, q, sizeof(q)));
            goto fail;
        }
        n->fn = pPerm;
    } else if (!strcmp(tok, "-readable") || !strcmp(tok, "-writable") || !strcmp(tok, "-executable")) {
        n->flags = tok[1] == 'r' ? R_OK : tok[1] == 'w' ? W_OK : X_OK;
        n->fn = pAccess;
    } else if (!strcmp(tok, "-user") || !strcmp(tok, "-group")) {
        NEED();
        if (tok[1] == 'u') {
            uid_t u;
            if (!findUserId(a, &u)) {
                findErr(f, "invalid user name or UID argument to -user: %s", findQ(a, q, sizeof(q)));
                goto fail;
            }
            n->num = u;
            n->fn = pUid;
        } else {
            gid_t g;
            if (!findGroupId(a, &g)) {
                findErr(f, "invalid group name or GID argument to -group: %s", findQ(a, q, sizeof(q)));
                goto fail;
            }
            n->num = g;
            n->fn = pGid;
        }
        n->cmp = '=';
    } else if (!strcmp(tok, "-uid") || !strcmp(tok, "-gid") || !strcmp(tok, "-links") || !strcmp(tok, "-inum")) {
        NEED();
        if (!findNumArg(a, &n->cmp, &n->num, false)) {
            findErr(f, "non-numeric argument to %s: %s", tok, findQ(a, q, sizeof(q)));
            goto fail;
        }
        n->fn = tok[1] == 'u' ? pUid : tok[1] == 'g' ? pGid : tok[1] == 'l' ? pLinks : pInum;
    } else if (!strcmp(tok, "-nouser")) {
        n->fn = pNouser;
    } else if (!strcmp(tok, "-nogroup")) {
        n->fn = pNogroup;
    } else if (!strcmp(tok, "-samefile")) {
        NEED();
        struct stat st;
        if (!findRefStat(f, a, &st)) goto fail;
        n->dev = st.st_dev;
        n->ino = st.st_ino;
        n->fn = pSamefile;
    } else if (!strcmp(tok, "-newer") || !strcmp(tok, "-anewer") || !strcmp(tok, "-cnewer") ||
               (!strncmp(tok, "-newer", 6) && strlen(tok) == 8)) {
        NEED();
        n->which = tok[1] == 'a' ? 'a' : tok[1] == 'c' ? 'c' : 'm';
        n->refWhich = 'm';
        if (strlen(tok) == 8) {
            n->which = tok[6];
            n->refWhich = tok[7];
            if (!strchr("acmB", n->which) || !strchr("acmBt", n->refWhich)) {
                findErr(f, "invalid predicate `%s'", tok);
                goto fail;
            }
        }
        if (n->refWhich == 't') {
            /* A literal time: @SECONDS or YYYY-MM-DD[ HH:MM[:SS]]. */
            struct tm tm;
            memset(&tm, 0, sizeof(tm));
            char *end = NULL;
            if (a[0] == '@') {
                n->ts.tv_sec = (time_t)strtoll(a + 1, &end, 10);
            } else if ((end = strptime(a, "%Y-%m-%d %H:%M:%S", &tm)) || (end = strptime(a, "%Y-%m-%d %H:%M", &tm)) ||
                       (end = strptime(a, "%Y-%m-%d", &tm))) {
                tm.tm_isdst = -1;
                n->ts.tv_sec = mktime(&tm);
            }
            if (!end || *end) {
                findErr(f, "I cannot figure out how to interpret %s as a date or time", findQ(a, q, sizeof(q)));
                goto fail;
            }
        } else {
            struct stat st;
            if (!findRefStat(f, a, &st)) goto fail;
            n->ts = findTime(&st, n->refWhich);
        }
        n->fn = pNewer;
    } else if (!strcmp(tok, "-atime") || !strcmp(tok, "-ctime") || !strcmp(tok, "-mtime") ||
               !strcmp(tok, "-amin") || !strcmp(tok, "-cmin") || !strcmp(tok, "-mmin") || !strcmp(tok, "-used")) {
        NEED();
        if (!findNumArg(a, &n->cmp, &n->num, true)) {
            findErr(f, "invalid argument `%s' to `%s'", a, tok);
            goto fail;
        }
        /* GNU's origins: days count from a day before now (or from midnight
         * after -daystart), shifted to the day's last second for "-N";
         * minutes from now; -used from zero. */
        bool minutes = tok[2] == 'm';
        bool used = tok[1] == 'u';
        struct timespec origin = f->dayStart;
        if (used) origin.tv_sec = origin.tv_nsec = 0;
        else if (minutes) origin.tv_sec += 86400;
        else if (n->cmp == '-') origin.tv_sec += 86400 - 1;
        n->window = minutes ? 60.0 : FIND_DAY;
        double secs = n->num * n->window;
        double whole = (double)(intmax_t)secs;
        long nsec = (long)((secs - whole) * 1e9);
        n->ts.tv_sec = origin.tv_sec - (time_t)whole;
        n->ts.tv_nsec = origin.tv_nsec - nsec;
        if (n->ts.tv_nsec < 0) {
            n->ts.tv_nsec += 1000000000;
            n->ts.tv_sec -= 1;
        }
        n->which = tok[1];
        n->fn = used ? pUsed : pTime;
    } else if (!strcmp(tok, "-fstype")) {
        NEED();
        n->s = a;
        n->fn = pFstype;
    } else if (!strcmp(tok, "-print") || !strcmp(tok, "-print0")) {
        n->out = stdout;
        n->nul = tok[6] == '0';
        n->fn = pPrint;
        n->action = true;
    } else if (!strcmp(tok, "-fprint") || !strcmp(tok, "-fprint0") || !strcmp(tok, "-fls")) {
        NEED();
        if (!(n->out = findOpenOut(f, a))) goto fail;
        n->nul = tok[7] == '0';
        n->fn = tok[2] == 'l' ? pLs : pPrint;
        n->action = true;
    } else if (!strcmp(tok, "-ls")) {
        n->out = stdout;
        n->fn = pLs;
        n->action = true;
    } else if (!strcmp(tok, "-printf") || !strcmp(tok, "-fprintf")) {
        if (tok[1] == 'f') {
            NEED();
            if (!(n->out = findOpenOut(f, a))) goto fail;
        } else {
            n->out = stdout;
        }
        NEED();
        if (!findParseFormat(f, n, a)) goto fail;
        n->fn = pPrintf;
        n->action = true;
    } else if (!strcmp(tok, "-exec") || !strcmp(tok, "-execdir") || !strcmp(tok, "-ok") || !strcmp(tok, "-okdir")) {
        n->inDir = strstr(tok, "dir") != NULL;
        n->ask = tok[1] == 'o';
        int startArg = f->pos, endArg = -1;
        for (int i = startArg; i < f->argc; i++) {
            if (!strcmp(f->argv[i], ";")) { endArg = i; break; }
            if (!n->ask && !strcmp(f->argv[i], "+") && i > startArg && !strcmp(f->argv[i - 1], "{}")) {
                endArg = i;
                n->plus = true;
                break;
            }
        }
        if (endArg < 0 || endArg == startArg) {
            findErr(f, "missing argument to `%s'", tok);
            goto fail;
        }
        n->argv = f->argv + startArg;
        n->argc = endArg - startArg;
        f->pos = endArg + 1;
        if (n->plus) {
            for (int i = 0; i < n->argc - 1; i++) {
                if (strstr(n->argv[i], "{}")) {
                    findErr(f, "Only one instance of {} is supported with -exec%s ... +", n->inDir ? "dir" : "");
                    goto fail;
                }
            }
            n->nextExec = f->execs;
            f->execs = n;
        }
        n->fn = pExec;
        n->action = true;
    } else if (!strcmp(tok, "-delete")) {
        n->fn = pDelete;
        n->action = true;
        f->hasDelete = true;
    } else if (!strcmp(tok, "-prune")) {
        n->fn = pPrune;
        f->hasPrune = true;
    } else if (!strcmp(tok, "-quit")) {
        n->fn = pQuit;
    } else {
        test = false;
        /* Options: always true, set for the whole run. */
        if (!strcmp(tok, "-maxdepth") || !strcmp(tok, "-mindepth")) {
            NEED();
            char *end;
            long v = strtol(a, &end, 10);
            if (!isdigit((unsigned char)*a) || *end || v < 0) {
                findErr(f, "Expected a positive decimal integer argument to %s, but got %s", tok, findQ(a, q, sizeof(q)));
                goto fail;
            }
            if (tok[2] == 'a') f->maxDepth = (int)v;
            else f->minDepth = (int)v;
            findPositional(f, tok);
        } else if (!strcmp(tok, "-depth") || !strcmp(tok, "-d")) {
            f->depthFirst = f->explicitDepth = true;
            findPositional(f, tok);
        } else if (!strcmp(tok, "-xdev") || !strcmp(tok, "-mount")) {
            f->xdev = true;
            findPositional(f, tok);
        } else if (!strcmp(tok, "-noleaf") || !strcmp(tok, "-nowarn") || !strcmp(tok, "-warn") ||
                   !strcmp(tok, "-ignore_readdir_race") || !strcmp(tok, "-noignore_readdir_race")) {
            if (!strcmp(tok, "-warn")) f->warn = true;
            if (!strcmp(tok, "-nowarn")) f->warn = false;
            if (!strcmp(tok, "-ignore_readdir_race")) f->ignoreRace = true;
            if (!strcmp(tok, "-noignore_readdir_race")) f->ignoreRace = false;
        } else if (!strcmp(tok, "-daystart")) {
            if (!f->daystart) {
                time_t t = f->dayStart.tv_sec + 86400;
                struct tm tm;
                if (localtime_r(&t, &tm)) t -= tm.tm_sec + tm.tm_min * 60 + tm.tm_hour * 3600;
                f->dayStart.tv_sec = t;
            }
            f->daystart = true;
        } else if (!strcmp(tok, "-follow")) {
            f->follow = 'L';
        } else if (!strcmp(tok, "-regextype")) {
            NEED();
            static const char *const types[] = {"findutils-default", "ed", "emacs", "gnu-awk", "grep", "posix-awk", "awk",
                                                "posix-basic", "posix-egrep", "egrep", "posix-extended",
                                                "posix-minimal-basic", "sed"};
            int t = -1;
            for (int i = 0; i < 13; i++)
                if (!strcmp(a, types[i])) t = i;
            if (t < 0) {
                fprintf(stderr, "find: Unknown regular expression type %s; valid types are ", findQ(a, q, sizeof(q)));
                for (int i = 0; i < 13; i++)
                    fprintf(stderr, "%s%s", findQ(types[i], q, sizeof(q)), i < 12 ? ", " : ".\n");
                f->status = 1;
                goto fail;
            }
            f->emacs = t == 0 || t == 2;
            f->regexType = (t == 3 || t == 5 || t == 6 || t == 8 || t == 9 || t == 10) ? REG_EXTENDED : 0;
        } else if (!strcmp(tok, "-help") || !strcmp(tok, "--help")) {
            fputs("Usage: find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]\n", stdout);
            f->quit = true;
            f->status = -1;
        } else if (!strcmp(tok, "-version") || !strcmp(tok, "--version")) {
            puts("find (SmallCLUE) 4.9.0");
            f->quit = true;
            f->status = -1;
        } else {
            findErr(f, "unknown predicate `%s'", tok);
            goto fail;
        }
    }
    if (test) {
        f->sawTest = true;
        f->lastTest = tok;
    }
#undef NEED
    return n;
fail:
    findFree(n);
    return NULL;
}

static bool findIsAnd(const char *t) { return t && (!strcmp(t, "-a") || !strcmp(t, "-and")); }
static bool findIsOr(const char *t) { return t && (!strcmp(t, "-o") || !strcmp(t, "-or")); }
static bool findIsNot(const char *t) { return t && (!strcmp(t, "!") || !strcmp(t, "-not")); }

static FindNode *findParseNot(Find *f) {
    const char *t = findNext(f);
    if (findIsNot(t)) {
        f->pos++;
        const char *nx = findNext(f);
        if (!nx || findIsAnd(nx) || findIsOr(nx) || !strcmp(nx, ",") || !strcmp(nx, ")")) {
            findErr(f, "expected an expression after '%s'", t);
            return NULL;
        }
        FindNode *c = findParseNot(f);
        if (!c) return NULL;
        FindNode *n = findNew(FN_NOT);
        n->l = c;
        return n;
    }
    return findParsePrimary(f);
}

static FindNode *findParseAnd(Find *f) {
    FindNode *l = findParseNot(f);
    if (!l) return NULL;
    for (;;) {
        const char *t = findNext(f);
        if (!t || findIsOr(t) || !strcmp(t, ",") || !strcmp(t, ")")) return l;
        if (findIsAnd(t)) {
            f->pos++;
            const char *nx = findNext(f);
            if (!nx || findIsAnd(nx) || findIsOr(nx) || !strcmp(nx, ",") || !strcmp(nx, ")")) {
                findErr(f, "expected an expression after '%s'", t);
                findFree(l);
                return NULL;
            }
        }
        FindNode *r = findParseNot(f);
        if (!r) { findFree(l); return NULL; }
        FindNode *n = findNew(FN_AND);
        n->l = l;
        n->r = r;
        l = n;
    }
}

static FindNode *findParseOr(Find *f) {
    FindNode *l = findParseAnd(f);
    if (!l) return NULL;
    while (findIsOr(findNext(f))) {
        const char *t = findNext(f);
        f->pos++;
        const char *nx = findNext(f);
        if (!nx || findIsAnd(nx) || findIsOr(nx) || !strcmp(nx, ",") || !strcmp(nx, ")")) {
            findErr(f, "expected an expression after '%s'", t);
            findFree(l);
            return NULL;
        }
        FindNode *r = findParseAnd(f);
        if (!r) { findFree(l); return NULL; }
        FindNode *n = findNew(FN_OR);
        n->l = l;
        n->r = r;
        l = n;
    }
    return l;
}

static FindNode *findParseComma(Find *f) {
    const char *t = findNext(f);
    if (findIsAnd(t) || findIsOr(t) || (t && !strcmp(t, ","))) {
        findErr(f, "invalid expression; you have used a binary operator '%s' with nothing before it.", t);
        return NULL;
    }
    FindNode *l = findParseOr(f);
    if (!l) return NULL;
    while ((t = findNext(f)) && !strcmp(t, ",")) {
        f->pos++;
        const char *nx = findNext(f);
        if (!nx || findIsAnd(nx) || findIsOr(nx) || !strcmp(nx, ",") || !strcmp(nx, ")")) {
            findErr(f, "expected an expression after ','");
            findFree(l);
            return NULL;
        }
        FindNode *r = findParseOr(f);
        if (!r) { findFree(l); return NULL; }
        FindNode *n = findNew(FN_COMMA);
        n->l = l;
        n->r = r;
        l = n;
    }
    return l;
}

static bool findHasAction(const FindNode *n) {
    if (!n) return false;
    if (n->kind == FN_PRED) return n->action;
    return findHasAction(n->l) || findHasAction(n->r);
}

static bool findExprStart(const char *a) {
    return (a[0] == '-' && a[1] != '\0') || !strcmp(a, "(") || !strcmp(a, ")") || !strcmp(a, "!") || !strcmp(a, ",");
}

int smallclueFindCommand(int argc, char **argv) {
    Find *f = (Find *)calloc(1, sizeof(Find));
    if (!f) return 1;
    f->follow = 'P';
    f->maxDepth = -1;
    f->lsInode = 9;
    f->lsBlocks = 6;
    f->lsLinks = 3;
    f->lsUser = 8;
    f->lsGroup = 8;
    f->lsSize = 8;
    clock_gettime(CLOCK_REALTIME, &f->now);
    f->dayStart = f->now;
    f->dayStart.tv_sec -= 86400;
    f->emacs = true;
    f->warn = isatty(0);
    int status = 0;
    char **paths = NULL;
    int npaths = 0;

    int i = 1;
    /* Leading -H, -L, -P, -D LIST and -O LEVEL. */
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-H") || !strcmp(a, "-L") || !strcmp(a, "-P")) f->follow = a[1];
        else if (!strcmp(a, "-D")) { if (++i >= argc) { findErr(f, "Missing argument after the -D option."); goto done; } }
        else if (!strncmp(a, "-O", 2) && a[2]) {}
        else if (!strcmp(a, "--")) { i++; break; }
        else break;
    }
    paths = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!paths) goto done;
    for (; i < argc && !findExprStart(argv[i]); i++) paths[npaths++] = argv[i];
    if (npaths == 0) paths[npaths++] = (char *)".";

    f->argv = argv;
    f->argc = argc;
    f->pos = i;
    FindNode *expr = NULL;
    if (f->pos < argc) {
        expr = findParseComma(f);
        if (!expr) {
            status = f->status == -1 ? 0 : 1;
            goto done;
        }
        if (f->pos < argc) {
            const char *t = argv[f->pos];
            if (!strcmp(t, ")")) findErr(f, "you have too many ')'");
            else findErr(f, "paths must precede expression: `%s'", t);
            findFree(expr);
            status = 1;
            goto done;
        }
    }
    if (f->status == -1) { status = 0; findFree(expr); goto done; }
    if (f->hasDelete && f->hasPrune && !f->explicitDepth) {
        findErr(f, "The -delete action automatically turns on -depth, but -prune does nothing when -depth is in "
                   "effect.  If you want to carry on anyway, just explicitly use the -depth option.");
        findFree(expr);
        status = 1;
        goto done;
    }
    if (f->hasDelete) f->depthFirst = true;
    if (!findHasAction(expr)) {
        FindNode *print = findNew(FN_PRED);
        print->fn = pPrint;
        print->out = stdout;
        print->action = true;
        if (expr) {
            FindNode *and = findNew(FN_AND);
            and->l = expr;
            and->r = print;
            expr = and;
        } else {
            expr = print;
        }
    }
    f->root = expr;

    for (int k = 0; k < npaths && !f->quit; k++) {
        const char *real = paths[k];
        f->nanc = 0;
        findVisit(f, paths[k], real, paths[k], 0);
    }
    for (FindNode *n = f->execs; n; n = n->nextExec) findFlush(f, n);
    status = f->status;
    findFree(expr);

done:
    fflush(stdout);
    for (size_t k = 0; k < f->nfiles; k++) {
        if (fclose(f->files[k]) != 0) status = 1;
        free(f->fileNames[k]);
    }
    free(f->files);
    free(f->fileNames);
    free(f->anc);
    free(f->mounts);
    free(paths);
    if (ferror(stdout)) status = 1;
    free(f);
    return status;
}
