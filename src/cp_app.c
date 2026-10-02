/*
 * cp and mv, compatible with GNU coreutils 9.
 *
 * The cp this replaces took -r, -a and -p only; the mv took no options at
 * all. Scripts that say `cp -v`, `cp -n`, `cp -u`, `cp -t DIR`, `cp -T`,
 * `cp -L/-P`, `cp --preserve=...`, `cp -l`, `cp -s`, `mv -b`, `mv -n` or
 * `mv -i` failed. These follow GNU: -t/-T and the target-directory rules
 * with GNU's messages; -n, -i, -f, -u/--update=WHEN, --remove-destination;
 * --backup/-b/-S with numbered and simple names; -v with GNU's text; for
 * cp, -r/-R, -a, -d, -L/-P/-H (following sources by default unless
 * recursive), -p and --preserve/--no-preserve (mode, ownership, nanosecond
 * timestamps, hard links), -l, -s, -x, --parents, special files recreated
 * under -R, and the into-itself refusal; for mv, rename with a copy-and-
 * remove fallback across file systems, the subdirectory refusal and the
 * directory-not-empty message.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cp_app.h"
#include "app_hooks.h"
#include "gnu_backup.h"
#include "gnu_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#define CP_ATIM(st) ((st)->st_atimespec)
#define CP_MTIM(st) ((st)->st_mtimespec)
#else
#define CP_ATIM(st) ((st)->st_atim)
#define CP_MTIM(st) ((st)->st_mtim)
#endif

typedef struct {
    dev_t dev;
    ino_t ino;
    char *dst;
} CpLink;

typedef struct {
    const char *prog;
    bool mv;
    bool recursive, force, interactive, noClobber, verbose, hardLink, symLink, parents;
    bool removeDest, oneFs, stripSlashes;
    char deref;            /* 'L', 'P', 'H'; 0: by -r */
    char update;           /* 0, 'o' older, 'a' all, 'n' none, 'f' none-fail */
    bool pMode, pOwner, pTime, pLinks;
    GnuBackup backup;
    const char *suffix;
    const char *targetDir;
    bool noTargetDir;
    int status;
    CpLink *links;
    size_t nlinks, clinks;
    mode_t umask;
    /* The first directory this operand created, to catch copying into
     * itself as GNU does: on meeting it as a source, stop the operand. */
    dev_t madeDev;
    ino_t madeIno;
    bool madeSet, intoSelf;
    bool mvVerbose;        /* mv -v across file systems: GNU narrates each step */
    const char *topSrc, *topDst;
} Cp;

static const char *cpQ(const char *s, char *buf, size_t n) {
    return gnuQuote(s, buf, n);
}

static void cpFail(Cp *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void cpFail(Cp *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", c->prog);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    c->status = 1;
}

/* The last component, without trailing slashes. */
static char *cpBase(const char *path) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && path[start - 1] != '/') start--;
    return strndup(path + start, len - start);
}

static bool cpYes(const char *prog, const char *question, const char *path) {
    char q[4096];
    fprintf(stderr, "%s: %s %s? ", prog, question, cpQ(path, q, sizeof(q)));
    fflush(stderr);
    return gnuYes();
}

/* Is `inner` (which need not exist yet) `outer` or inside it? Both are
 * made canonical: the deepest existing ancestor of `inner` through
 * realpath, with the rest appended. */
static bool cpWithin(const char *outer, const char *inner) {
    char ro[PATH_MAX], ri[PATH_MAX], head[PATH_MAX], tail[PATH_MAX] = "";
    if (!realpath(outer, ro)) return false;
    snprintf(head, sizeof(head), "%s", inner);
    while (!realpath(head, ri)) {
        size_t len = strlen(head);
        while (len > 1 && head[len - 1] == '/') head[--len] = '\0';
        char *slash = strrchr(head, '/');
        char t[PATH_MAX];
        snprintf(t, sizeof(t), "/%s%s", slash ? slash + 1 : head, tail);
        snprintf(tail, sizeof(tail), "%s", t);
        if (!slash) snprintf(head, sizeof(head), ".");
        else if (slash == head) head[1] = '\0';
        else *slash = '\0';
    }
    size_t l = strlen(ri);
    snprintf(ri + l, sizeof(ri) - l, "%s", tail);
    size_t ol = strlen(ro);
    if (ol == 1) return true;   /* everything is inside / */
    return !strncmp(ri, ro, ol) && (ri[ol] == '\0' || ri[ol] == '/');
}

/* --- Preserving attributes. --- */

static void cpPreserve(Cp *c, const char *dst, const struct stat *src, bool isLink, bool created) {
    if (c->pOwner && (isLink ? lchown(dst, src->st_uid, src->st_gid) : chown(dst, src->st_uid, src->st_gid)) != 0) {
        /* Not being root is not an error worth reporting, as in GNU. */
        if (errno != EPERM && errno != EINVAL) {
            char q[4096];
            fprintf(stderr, "%s: failed to preserve ownership for %s: %s\n", c->prog, cpQ(dst, q, sizeof(q)), strerror(errno));
        }
    }
    if (!isLink) {
        if (c->pMode) (void)chmod(dst, src->st_mode & 07777);
        else if (created && S_ISDIR(src->st_mode)) (void)chmod(dst, src->st_mode & 0777 & ~c->umask);
    }
    if (c->pTime) {
        struct timespec ts[2] = {CP_ATIM(src), CP_MTIM(src)};
        if (utimensat(AT_FDCWD, dst, ts, isLink ? AT_SYMLINK_NOFOLLOW : 0) != 0 && !isLink) {
            char q[4096];
            fprintf(stderr, "%s: preserving times for %s: %s\n", c->prog, cpQ(dst, q, sizeof(q)), strerror(errno));
            c->status = 1;
        }
    }
}

/* --- Copying. --- */

static bool cpData(Cp *c, const char *srcDisp, const char *src, const char *dstDisp, const char *dst,
                   const struct stat *st, bool existed) {
    char q[4096];
    int in = open(src, O_RDONLY);
    if (in < 0) {
        cpFail(c, "cannot open %s for reading: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
        return false;
    }
    int out = -1;
    if (existed) {
        out = open(dst, O_WRONLY | O_TRUNC);
        if (out < 0 && c->force && errno != ENOENT) {
            if (unlink(dst) == 0) existed = false;
        }
    }
    if (out < 0) out = open(dst, O_WRONLY | O_CREAT | (existed ? O_TRUNC : O_EXCL), st->st_mode & 0777);
    if (out < 0) {
        cpFail(c, "cannot create regular file %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
        close(in);
        return false;
    }
    char *buf = (char *)malloc(131072);
    bool ok = buf != NULL;
    while (ok) {
        ssize_t n = read(in, buf, 131072);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            cpFail(c, "error reading %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
            ok = false;
            break;
        }
        if (n == 0) break;
        for (ssize_t w = 0; w < n;) {
            ssize_t k = write(out, buf + w, (size_t)(n - w));
            if (k < 0 && errno == EINTR) continue;
            if (k < 0) {
                cpFail(c, "error writing %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
                ok = false;
                break;
            }
            w += k;
        }
    }
    free(buf);
    close(in);
    if (close(out) != 0 && ok) {
        cpFail(c, "error writing %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
        ok = false;
    }
    return ok;
}

static bool cpCopy(Cp *c, const char *srcDisp, const char *src, const char *dstDisp, const char *dst, bool top,
                   dev_t topDev);

typedef struct {
    ino_t ino;
    char *name;
} CpEntry;

static int cpByInode(const void *a, const void *b) {
    ino_t x = ((const CpEntry *)a)->ino, y = ((const CpEntry *)b)->ino;
    return (x > y) - (x < y);
}

static bool cpDir(Cp *c, const char *srcDisp, const char *src, const char *dstDisp, const char *dst,
                  const struct stat *st, bool dstExists, dev_t topDev) {
    char q[4096];
    bool created = false;
    if (!dstExists) {
        if (mkdir(dst, (st->st_mode & 0777) | 0700) != 0) {
            cpFail(c, "cannot create directory %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
            return false;
        }
        created = true;
        struct stat made;
        if (!c->madeSet && stat(dst, &made) == 0) {
            c->madeDev = made.st_dev;
            c->madeIno = made.st_ino;
            c->madeSet = true;
        }
    }
    if (c->verbose) {
        char q2[4096];
        printf("%s -> %s\n", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
    } else if (c->mvVerbose && created) {
        printf("created directory %s\n", cpQ(dstDisp, q, sizeof(q)));
    }
    bool ok = true;
    if (!c->oneFs || st->st_dev == topDev) {
        DIR *d = opendir(src);
        if (!d) {
            cpFail(c, "cannot access %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
            return false;
        }
        /* In inode order, as GNU's savedir reads them. */
        CpEntry *names = NULL;
        size_t n = 0, cap = 0;
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 32;
                CpEntry *v = (CpEntry *)realloc(names, cap * sizeof(CpEntry));
                if (!v) break;
                names = v;
            }
            names[n].ino = de->d_ino;
            names[n++].name = strdup(de->d_name);
        }
        closedir(d);
        qsort(names, n, sizeof(CpEntry), cpByInode);
        for (size_t i = 0; i < n; i++) {
            if (!c->intoSelf) {
                char *sd = gnuPathJoin(srcDisp, names[i].name), *sr = gnuPathJoin(src, names[i].name);
                char *dd = gnuPathJoin(dstDisp, names[i].name), *dr = gnuPathJoin(dst, names[i].name);
                if (sd && sr && dd && dr && !cpCopy(c, sd, sr, dd, dr, false, topDev)) ok = false;
                free(sd); free(sr); free(dd); free(dr);
            }
            free(names[i].name);
        }
        free(names);
    }
    cpPreserve(c, dst, st, false, created);
    return ok;
}

/* Copies one name: the heart of cp (and of mv across file systems). */
static bool cpCopy(Cp *c, const char *srcDisp, const char *src, const char *dstDisp, const char *dst, bool top,
                   dev_t topDev) {
    char q[4096], q2[4096];
    struct stat st, dst_st;
    bool follow = c->deref == 'L' || (c->deref == 'H' && top);
    if ((follow ? stat(src, &st) : lstat(src, &st)) != 0) {
        cpFail(c, "cannot stat %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
        return false;
    }
    if (top) topDev = st.st_dev;
    if (S_ISDIR(st.st_mode) && !c->recursive) {
        cpFail(c, "-r not specified; omitting directory %s", cpQ(srcDisp, q, sizeof(q)));
        return false;
    }
    bool dstExists = lstat(dst, &dst_st) == 0;
    /* A symlink destination is written through, as GNU does, unless we are
     * about to replace it anyway. */
    struct stat dst_follow;
    bool dstIsDir = dstExists && (S_ISDIR(dst_st.st_mode) ||
                                  (S_ISLNK(dst_st.st_mode) && stat(dst, &dst_follow) == 0 && S_ISDIR(dst_follow.st_mode)));
    if (dstExists) {
        /* The same file under two names (or one): copying would destroy it. */
        struct stat a, b;
        if (stat(src, &a) == 0 && stat(dst, &b) == 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
            !S_ISDIR(a.st_mode)) {
            cpFail(c, "%s and %s are the same file", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
            return false;
        }
        if (S_ISDIR(st.st_mode) && !dstIsDir) {
            cpFail(c, "cannot overwrite non-directory %s with directory %s", cpQ(dstDisp, q, sizeof(q)),
                   cpQ(srcDisp, q2, sizeof(q2)));
            return false;
        }
        if (!S_ISDIR(st.st_mode) && dstIsDir) {
            cpFail(c, "cannot overwrite directory %s with non-directory %s", cpQ(dstDisp, q, sizeof(q)),
                   cpQ(srcDisp, q2, sizeof(q2)));
            return false;
        }
        if (!S_ISDIR(st.st_mode)) {
            if (c->noClobber) return true;
            if (c->update == 'n') return true;
            if (c->update == 'f') {
                cpFail(c, "not replacing %s", cpQ(dstDisp, q, sizeof(q)));
                return false;
            }
            if (c->update == 'o') {
                struct timespec sm = CP_MTIM(&st), dm = CP_MTIM(&dst_st);
                if (dm.tv_sec > sm.tv_sec || (dm.tv_sec == sm.tv_sec && dm.tv_nsec >= sm.tv_nsec)) return true;
            }
            if (c->interactive && !cpYes(c->prog, "overwrite", dstDisp)) {
                c->status = 1;
                return true;
            }
        }
    }
    if (S_ISDIR(st.st_mode)) {
        if (top) {
            c->madeSet = c->intoSelf = false;
            c->topSrc = srcDisp;
            c->topDst = dstDisp;
        } else if (c->madeSet && st.st_dev == c->madeDev && st.st_ino == c->madeIno) {
            cpFail(c, "cannot copy a directory, %s, into itself, %s", cpQ(c->topSrc, q, sizeof(q)),
                   cpQ(c->topDst, q2, sizeof(q2)));
            c->intoSelf = true;
            return false;
        }
        return cpDir(c, srcDisp, src, dstDisp, dst, &st, dstExists && dstIsDir, topDev);
    }

    /* A non-directory replaces what is there: back it up, or remove it
     * when a link of any kind is to be made in its place. */
    char backupName[PATH_MAX] = "";
    if (dstExists && c->backup != GNU_BACKUP_NONE) {
        if (!gnuBackupName(c->backup, c->suffix, dst, backupName, sizeof(backupName)) || rename(dst, backupName) != 0) {
            cpFail(c, "cannot backup %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
            return false;
        }
        dstExists = false;
    } else if (dstExists && (c->removeDest || S_ISLNK(st.st_mode) || c->hardLink || c->symLink ||
                             (!S_ISREG(st.st_mode) && c->recursive))) {
        if (c->symLink || c->hardLink) {
            if (!c->force && !c->removeDest) {
                cpFail(c, c->symLink ? "cannot create symbolic link %s to %s: File exists"
                                     : "cannot create hard link %s to %s: File exists",
                       cpQ(dstDisp, q, sizeof(q)), cpQ(srcDisp, q2, sizeof(q2)));
                return false;
            }
        }
        if (unlink(dst) != 0 && errno != ENOENT) {
            cpFail(c, "cannot remove %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
            return false;
        }
        dstExists = false;
    }

    bool ok = true;
    bool isLink = false, linkedCopy = false;
    if (c->symLink) {
        if (srcDisp[0] != '/' && strchr(dstDisp, '/')) {
            /* GNU allows relative targets only for links made in . */
            char dir[PATH_MAX];
            snprintf(dir, sizeof(dir), "%s", dst);
            char *slash = strrchr(dir, '/');
            if (slash) *slash = '\0';
            struct stat a, b;
            if (stat(dir, &a) != 0 || stat(".", &b) != 0 || a.st_ino != b.st_ino || a.st_dev != b.st_dev) {
                cpFail(c, "%s: can make relative symbolic links only in current directory", gnuQuoteMaybe(dstDisp, q, sizeof(q)));
                return false;
            }
        }
        if (symlink(src, dst) != 0) {
            cpFail(c, "cannot create symbolic link %s to %s: %s", cpQ(dstDisp, q, sizeof(q)), cpQ(srcDisp, q2, sizeof(q2)),
                   strerror(errno));
            return false;
        }
        isLink = true;
    } else if (c->hardLink) {
        if (link(src, dst) != 0) {
            cpFail(c, "cannot create hard link %s to %s: %s", cpQ(dstDisp, q, sizeof(q)), cpQ(srcDisp, q2, sizeof(q2)),
                   strerror(errno));
            return false;
        }
    } else {
        /* --preserve=links: a second name for an inode already copied. */
        if (c->pLinks && st.st_nlink > 1) {
            for (size_t i = 0; i < c->nlinks; i++) {
                if (c->links[i].dev == st.st_dev && c->links[i].ino == st.st_ino) {
                    if (link(c->links[i].dst, dst) != 0) {
                        cpFail(c, "cannot create hard link %s to %s: %s", cpQ(dstDisp, q, sizeof(q)),
                               cpQ(c->links[i].dst, q2, sizeof(q2)), strerror(errno));
                        return false;
                    }
                    linkedCopy = true;
                    goto done;
                }
            }
        }
        if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t len = readlink(src, target, sizeof(target) - 1);
            if (len < 0) {
                cpFail(c, "cannot read symbolic link %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
                return false;
            }
            target[len] = '\0';
            if (symlink(target, dst) != 0) {
                cpFail(c, "cannot create symbolic link %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
                return false;
            }
            isLink = true;
        } else if (S_ISREG(st.st_mode) || !c->recursive) {
            /* Special files are read like files unless copying a tree. */
            ok = cpData(c, srcDisp, src, dstDisp, dst, &st, dstExists);
        } else if (S_ISFIFO(st.st_mode)) {
            if (mkfifo(dst, st.st_mode & 0777) != 0) {
                cpFail(c, "cannot create fifo %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
                return false;
            }
        } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) || S_ISSOCK(st.st_mode)) {
            if (mknod(dst, st.st_mode, st.st_rdev) != 0) {
                cpFail(c, "cannot create special file %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
                return false;
            }
        }
        if (ok && c->pLinks && st.st_nlink > 1) {
            if (c->nlinks == c->clinks) {
                c->clinks = c->clinks ? c->clinks * 2 : 16;
                CpLink *v = (CpLink *)realloc(c->links, c->clinks * sizeof(CpLink));
                if (v) c->links = v;
            }
            if (c->nlinks < c->clinks) {
                c->links[c->nlinks].dev = st.st_dev;
                c->links[c->nlinks].ino = st.st_ino;
                c->links[c->nlinks].dst = strdup(dst);
                c->nlinks++;
            }
        }
        if (ok) cpPreserve(c, dst, &st, isLink, !dstExists);
    }
done:
    if (ok && c->mvVerbose && !linkedCopy) {
        printf("copied %s -> %s\n", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
    } else if (ok && c->verbose && !c->mv) {
        printf("%s -> %s", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
        if (backupName[0]) printf(" (backup: %s)", cpQ(backupName, q, sizeof(q)));
        putchar('\n');
    }
    return ok;
}

/* --- mv. --- */

static bool cpRemoveTree(Cp *c, const char *disp, const char *path, bool verbose) {
    char q[4096];
    struct stat st;
    if (lstat(path, &st) != 0) return true;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *de;
            CpEntry *names = NULL;
            size_t n = 0, cap = 0;
            while ((de = readdir(d))) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                if (n == cap) {
                    cap = cap ? cap * 2 : 32;
                    CpEntry *v = (CpEntry *)realloc(names, cap * sizeof(CpEntry));
                    if (!v) break;
                    names = v;
                }
                names[n].ino = de->d_ino;
                names[n++].name = strdup(de->d_name);
            }
            closedir(d);
            qsort(names, n, sizeof(CpEntry), cpByInode);
            for (size_t i = 0; i < n; i++) {
                char *cd = gnuPathJoin(disp, names[i].name), *cp = gnuPathJoin(path, names[i].name);
                if (cd && cp) cpRemoveTree(c, cd, cp, verbose);
                free(cd); free(cp); free(names[i].name);
            }
            free(names);
        }
        if (rmdir(path) != 0) {
            cpFail(c, "cannot remove %s: %s", cpQ(disp, q, sizeof(q)), strerror(errno));
            return false;
        }
        if (verbose) printf("removed directory %s\n", cpQ(disp, q, sizeof(q)));
        return true;
    }
    if (unlink(path) != 0) {
        cpFail(c, "cannot remove %s: %s", cpQ(disp, q, sizeof(q)), strerror(errno));
        return false;
    }
    if (verbose) printf("removed %s\n", cpQ(disp, q, sizeof(q)));
    return true;
}

static bool cpMove(Cp *c, const char *srcDisp, const char *src, const char *dstDisp, const char *dst) {
    char q[4096], q2[4096];
    struct stat st, dst_st;
    if (lstat(src, &st) != 0) {
        cpFail(c, "cannot stat %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(errno));
        return false;
    }
    bool dstExists = lstat(dst, &dst_st) == 0;
    if (dstExists) {
        if (st.st_dev == dst_st.st_dev && st.st_ino == dst_st.st_ino) {
            cpFail(c, "%s and %s are the same file", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
            return false;
        }
        if (c->noClobber || c->update == 'n') return true;
        if (c->update == 'f') {
            cpFail(c, "not replacing %s", cpQ(dstDisp, q, sizeof(q)));
            return false;
        }
        if (c->update == 'o' && !S_ISDIR(st.st_mode)) {
            struct timespec sm = CP_MTIM(&st), dm = CP_MTIM(&dst_st);
            if (dm.tv_sec > sm.tv_sec || (dm.tv_sec == sm.tv_sec && dm.tv_nsec >= sm.tv_nsec)) return true;
        }
        if (c->interactive) {
            if (!cpYes(c->prog, "overwrite", dstDisp)) {
                c->status = 1;
                return true;
            }
        } else if (!c->force && !S_ISLNK(dst_st.st_mode) && access(dst, W_OK) != 0 && isatty(0)) {
            char mode[12];
            static const char rwx[] = "rwxrwxrwx";
            for (int i = 0; i < 9; i++) mode[i] = (dst_st.st_mode & (0400 >> i)) ? rwx[i] : '-';
            mode[9] = '\0';
            fprintf(stderr, "%s: replace %s, overriding mode %04o (%s)? ", c->prog, cpQ(dstDisp, q, sizeof(q)),
                    (unsigned)(dst_st.st_mode & 07777), mode);
            fflush(stderr);
            if (!gnuYes()) {
                c->status = 1;
                return true;
            }
        }
        if (S_ISDIR(st.st_mode) && !S_ISDIR(dst_st.st_mode)) {
            cpFail(c, "cannot overwrite non-directory %s with directory %s", cpQ(dstDisp, q, sizeof(q)),
                   cpQ(srcDisp, q2, sizeof(q2)));
            return false;
        }
        if (!S_ISDIR(st.st_mode) && S_ISDIR(dst_st.st_mode)) {
            cpFail(c, "cannot overwrite directory %s with non-directory %s", cpQ(dstDisp, q, sizeof(q)),
                   cpQ(srcDisp, q2, sizeof(q2)));
            return false;
        }
    }
    if (S_ISDIR(st.st_mode) && cpWithin(src, dst)) {
        cpFail(c, "cannot move %s to a subdirectory of itself, %s", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
        return false;
    }
    char backupName[PATH_MAX] = "";
    if (dstExists && c->backup != GNU_BACKUP_NONE) {
        if (!gnuBackupName(c->backup, c->suffix, dst, backupName, sizeof(backupName)) || rename(dst, backupName) != 0) {
            cpFail(c, "cannot backup %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
            return false;
        }
    }
    if (rename(src, dst) != 0) {
        int err = errno;
        if (err == EXDEV) {
            /* Across file systems: copy everything, then remove the source. */
            Cp sub = *c;
            sub.recursive = true;
            sub.deref = 'P';
            sub.pMode = sub.pOwner = sub.pTime = sub.pLinks = true;
            sub.verbose = false;
            sub.mvVerbose = c->verbose;
            sub.interactive = sub.noClobber = false;
            sub.update = 0;
            sub.backup = GNU_BACKUP_NONE;
            sub.force = true;
            sub.status = 0;
            if (dstExists && !backupName[0] && S_ISDIR(dst_st.st_mode)) {
                if (rmdir(dst) != 0) {
                    cpFail(c, "cannot overwrite %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(errno));
                    return false;
                }
            }
            bool ok = cpCopy(&sub, srcDisp, src, dstDisp, dst, true, 0) && sub.status == 0;
            c->links = sub.links;
            c->nlinks = sub.nlinks;
            c->clinks = sub.clinks;
            if (!ok) {
                c->status = 1;
                return false;
            }
            if (!cpRemoveTree(c, srcDisp, src, c->verbose)) return false;
            return true;   /* GNU narrated the copy; no "renamed" line */
        } else if (err == ENOTEMPTY || err == EEXIST) {
            cpFail(c, "cannot overwrite %s: %s", cpQ(dstDisp, q, sizeof(q)), strerror(ENOTEMPTY));
            return false;
        } else if (err == ENOTDIR && srcDisp[strlen(srcDisp) - 1] == '/') {
            cpFail(c, "cannot stat %s: %s", cpQ(srcDisp, q, sizeof(q)), strerror(err));
            return false;
        } else {
            cpFail(c, "cannot move %s to %s: %s", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)), strerror(err));
            return false;
        }
    }
    if (c->verbose) {
        printf("renamed %s -> %s", cpQ(srcDisp, q, sizeof(q)), cpQ(dstDisp, q2, sizeof(q2)));
        if (backupName[0]) printf(" (backup: %s)", cpQ(backupName, q, sizeof(q)));
        putchar('\n');
    }
    return true;
}

/* --- Options. --- */

static int cpTry(const Cp *c) {
    fprintf(stderr, "Try '%s --help' for more information.\n", c->prog);
    return 1;
}

static void cpUsage(const Cp *c) {
    if (c->mv) {
        fputs("Usage: mv [OPTION]... [-T] SOURCE DEST\n"
              "  or:  mv [OPTION]... SOURCE... DIRECTORY\n"
              "  or:  mv [OPTION]... -t DIRECTORY SOURCE...\n"
              "Rename SOURCE to DEST, or move SOURCE(s) to DIRECTORY.\n\n"
              "      --backup[=CONTROL]       make a backup of each existing destination file\n"
              "  -b                           like --backup but does not accept an argument\n"
              "  -f, --force                  do not prompt before overwriting\n"
              "  -i, --interactive            prompt before overwrite\n"
              "  -n, --no-clobber             do not overwrite an existing file\n"
              "      --strip-trailing-slashes  remove any trailing slashes from each SOURCE\n"
              "  -S, --suffix=SUFFIX          override the usual backup suffix\n"
              "  -t, --target-directory=DIRECTORY  move all SOURCE arguments into DIRECTORY\n"
              "  -T, --no-target-directory    treat DEST as a normal file\n"
              "  -u, --update[=UPDATE]        control which existing files are updated;\n"
              "                                 UPDATE={all,none,none-fail,older(default)}\n"
              "  -v, --verbose                explain what is being done\n",
              stdout);
        return;
    }
    fputs("Usage: cp [OPTION]... [-T] SOURCE DEST\n"
          "  or:  cp [OPTION]... SOURCE... DIRECTORY\n"
          "  or:  cp [OPTION]... -t DIRECTORY SOURCE...\n"
          "Copy SOURCE to DEST, or multiple SOURCE(s) to DIRECTORY.\n\n"
          "  -a, --archive                same as -dR --preserve=all\n"
          "      --backup[=CONTROL]       make a backup of each existing destination file\n"
          "  -b                           like --backup but does not accept an argument\n"
          "  -d                           same as --no-dereference --preserve=links\n"
          "  -f, --force                  if an existing destination file cannot be\n"
          "                                 opened, remove it and try again\n"
          "  -i, --interactive            prompt before overwrite\n"
          "  -H                           follow command-line symbolic links in SOURCE\n"
          "  -l, --link                   hard link files instead of copying\n"
          "  -L, --dereference            always follow symbolic links in SOURCE\n"
          "  -n, --no-clobber             do not overwrite an existing file\n"
          "  -P, --no-dereference         never follow symbolic links in SOURCE\n"
          "  -p                           same as --preserve=mode,ownership,timestamps\n"
          "      --preserve[=ATTR_LIST]   preserve the specified attributes\n"
          "      --no-preserve=ATTR_LIST  don't preserve the specified attributes\n"
          "      --parents                use full source file name under DIRECTORY\n"
          "  -R, -r, --recursive          copy directories recursively\n"
          "      --remove-destination     remove each existing destination file before\n"
          "                                 attempting to open it\n"
          "      --strip-trailing-slashes  remove any trailing slashes from each SOURCE\n"
          "  -s, --symbolic-link          make symbolic links instead of copying\n"
          "  -S, --suffix=SUFFIX          override the usual backup suffix\n"
          "  -t, --target-directory=DIRECTORY  copy all SOURCE arguments into DIRECTORY\n"
          "  -T, --no-target-directory    treat DEST as a normal file\n"
          "  -u, --update[=UPDATE]        control which existing files are updated;\n"
          "                                 UPDATE={all,none,none-fail,older(default)}\n"
          "  -v, --verbose                explain what is being done\n"
          "  -x, --one-file-system        stay on this file system\n",
          stdout);
}

/* --preserve / --no-preserve lists; false after a message. */
static bool cpAttrs(Cp *c, const char *list, bool on, const char *opt) {
    char *copy = strdup(list ? list : "mode,ownership,timestamps");
    if (!copy) return false;
    bool ok = true;
    char *save = NULL;
    for (char *a = strtok_r(copy, ",", &save); a; a = strtok_r(NULL, ",", &save)) {
        if (!strcmp(a, "mode")) c->pMode = on;
        else if (!strcmp(a, "ownership")) c->pOwner = on;
        else if (!strcmp(a, "timestamps")) c->pTime = on;
        else if (!strcmp(a, "links")) c->pLinks = on;
        else if (!strcmp(a, "context") || !strcmp(a, "xattr")) {}
        else if (!strcmp(a, "all")) c->pMode = c->pOwner = c->pTime = c->pLinks = on;
        else {
            char q[512], q2[64];
            fprintf(stderr, "%s: invalid argument %s for %s\nValid arguments are:\n", c->prog, gnuQuoteLocale(a, q, sizeof(q)),
                    gnuQuoteLocale(opt, q2, sizeof(q2)));
            static const char *const names[] = {"mode", "timestamps", "ownership", "links", "context", "xattr", "all"};
            for (int i = 0; i < 7; i++) fprintf(stderr, "  - %s\n", gnuQuoteLocale(names[i], q, sizeof(q)));
            ok = false;
            break;
        }
    }
    free(copy);
    return ok;
}

typedef struct {
    const char *name;
    char shortEq;
    int arg;          /* 0 none, 1 required, 2 optional */
    bool cpOnly;
} CpLong;

static const CpLong cpLongs[] = {
    {"archive", 'a', 0, true}, {"attributes-only", 1, 0, true}, {"backup", 2, 2, false},
    {"copy-contents", 3, 0, true}, {"debug", 4, 0, false}, {"dereference", 'L', 0, true},
    {"force", 'f', 0, false}, {"help", 5, 0, false}, {"interactive", 'i', 0, false},
    {"keep-directory-symlink", 6, 0, true}, {"link", 'l', 0, true}, {"no-clobber", 'n', 0, false},
    {"no-copy", 7, 0, false}, {"no-dereference", 'P', 0, true}, {"no-preserve", 8, 1, true},
    {"no-target-directory", 'T', 0, false}, {"one-file-system", 'x', 0, true}, {"parents", 9, 0, true},
    {"preserve", 10, 2, true}, {"recursive", 'R', 0, true}, {"reflink", 11, 2, true},
    {"remove-destination", 12, 0, true}, {"sparse", 13, 1, true}, {"strip-trailing-slashes", 14, 0, false},
    {"suffix", 'S', 1, false}, {"symbolic-link", 's', 0, true}, {"target-directory", 't', 1, false},
    {"update", 'u', 2, false}, {"verbose", 'v', 0, false}, {"version", 15, 0, false},
};

/* A single-letter option (also what the long ones mean). */
static void cpShort(Cp *c, char ch, bool *makeBackup) {
    switch (ch) {
    case 'a': c->recursive = true; c->deref = 'P'; c->pMode = c->pOwner = c->pTime = c->pLinks = true; break;
    case 'b': *makeBackup = true; break;
    case 'd': c->deref = 'P'; c->pLinks = true; break;
    case 'f': c->force = true; c->interactive = false; c->noClobber = false; break;
    case 'H': c->deref = 'H'; break;
    case 'i': c->interactive = true; c->noClobber = false; c->force = false; break;
    case 'l': c->hardLink = true; break;
    case 'L': c->deref = 'L'; break;
    case 'n': c->noClobber = true; c->interactive = false; c->force = false; break;
    case 'P': c->deref = 'P'; break;
    case 'p': c->pMode = c->pOwner = c->pTime = true; break;
    case 'r': case 'R': c->recursive = true; break;
    case 's': c->symLink = true; break;
    case 'T': c->noTargetDir = true; break;
    case 'u': c->update = 'o'; break;
    case 'v': c->verbose = true; break;
    case 'x': c->oneFs = true; break;
    default: break;
    }
}

static int cpMain(int argc, char **argv, bool mv) {
    Cp c;
    memset(&c, 0, sizeof(c));
    c.prog = mv ? "mv" : "cp";
    c.mv = mv;
    c.backup = GNU_BACKUP_NONE;
    mode_t um = umask(0);
    umask(um);
    c.umask = um;
    bool makeBackup = false;
    const char *backupControl = NULL, *suffix = NULL;
    char **ops = (char **)calloc((size_t)argc + 1, sizeof(char *));
    size_t nops = 0;
    int status = 1;
    if (!ops) return 1;

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
            const CpLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(cpLongs) / sizeof(cpLongs[0]); k++) {
                if ((cpLongs[k].cpOnly && mv) || strncmp(cpLongs[k].name, opt, len)) continue;
                if (strlen(cpLongs[k].name) == len) { m = &cpLongs[k]; matches = 1; break; }
                m = &cpLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "%s: option '%s' is ambiguous\n" : "%s: unrecognized option '%s'\n", c.prog, arg);
                status = cpTry(&c);
                goto done;
            }
            const char *val = NULL;
            if (eq) {
                if (m->arg == 0) {
                    fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n", c.prog, m->name);
                    status = cpTry(&c);
                    goto done;
                }
                val = eq + 1;
            } else if (m->arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "%s: option '--%s' requires an argument\n", c.prog, m->name);
                    status = cpTry(&c);
                    goto done;
                }
                val = argv[++i];
            }
            switch (m->shortEq) {
            case 2: makeBackup = true; if (val) backupControl = val; break;
            case 5: cpUsage(&c); status = 0; goto done;
            case 15: printf("%s (SmallCLUE) 9.4\n", c.prog); status = 0; goto done;
            case 8: if (!cpAttrs(&c, val, false, "--no-preserve")) { status = cpTry(&c); goto done; } break;
            case 9: c.parents = true; break;
            case 10: if (!cpAttrs(&c, val, true, "--preserve")) { status = cpTry(&c); goto done; } break;
            case 12: c.removeDest = true; break;
            case 14: c.stripSlashes = true; break;
            case 'u':
                if (!val || !strcmp(val, "older")) c.update = 'o';
                else if (!strcmp(val, "all")) c.update = 'a';
                else if (!strcmp(val, "none")) c.update = 'n';
                else if (!strcmp(val, "none-fail")) c.update = 'f';
                else {
                    char q[512], q2[64];
                    fprintf(stderr, "%s: invalid argument %s for %s\nValid arguments are:\n", c.prog,
                            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale("--update", q2, sizeof(q2)));
                    static const char *const whens[] = {"all", "none", "none-fail", "older"};
                    for (int w = 0; w < 4; w++) fprintf(stderr, "  - %s\n", gnuQuoteLocale(whens[w], q, sizeof(q)));
                    status = cpTry(&c);
                    goto done;
                }
                break;
            case 'S': suffix = val; makeBackup = true; break;
            case 't': c.targetDir = val; break;
            default:
                cpShort(&c, m->shortEq, &makeBackup);
                break;
            }
            continue;
        }
        for (const char *p = arg + 1; *p; p++) {
            char ch = *p;
            const char *allowed = mv ? "bfinTuvZtS" : "abdfHilLnPprRsTuvxZtS";
            if (!strchr(allowed, ch)) {
                fprintf(stderr, "%s: invalid option -- '%c'\n", c.prog, ch);
                status = cpTry(&c);
                goto done;
            }
            if (ch == 't' || ch == 'S') {
                const char *val = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
                if (!val) {
                    fprintf(stderr, "%s: option requires an argument -- '%c'\n", c.prog, ch);
                    status = cpTry(&c);
                    goto done;
                }
                if (ch == 't') c.targetDir = val;
                else { suffix = val; makeBackup = true; }
                break;
            }
            cpShort(&c, ch, &makeBackup);
        }
    }
    if (makeBackup) {
        const char *control = backupControl ? backupControl : getenv("VERSION_CONTROL");
        if (!gnuBackupParse(control, &c.backup)) {
            gnuBackupComplain(c.prog, control);
            status = cpTry(&c);
            goto done;
        }
        if (c.noClobber) {
            fprintf(stderr, "%s: --backup is mutually exclusive with -n or --update=none-fail\n", c.prog);
            status = cpTry(&c);
            goto done;
        }
    }
    c.suffix = gnuBackupSuffix(suffix);
    if (!c.deref) c.deref = c.recursive ? 'P' : 'L';
    if (c.targetDir && c.noTargetDir) {
        fprintf(stderr, "%s: cannot combine --target-directory (-t) and --no-target-directory (-T)\n", c.prog);
        goto done;
    }
    if (c.stripSlashes) {
        for (size_t k = 0; k < nops; k++) {
            size_t l = strlen(ops[k]);
            while (l > 1 && ops[k][l - 1] == '/') ops[k][--l] = '\0';
        }
    }

    char q[4096];
    if (nops == 0) {
        fprintf(stderr, "%s: missing file operand\n", c.prog);
        status = cpTry(&c);
        goto done;
    }
    const char *dir = NULL;
    size_t nsrc = nops;
    if (c.targetDir) {
        struct stat st;
        if (stat(c.targetDir, &st) != 0) {
            fprintf(stderr, "%s: target directory %s: %s\n", c.prog, cpQ(c.targetDir, q, sizeof(q)), strerror(errno));
            goto done;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "%s: target directory %s: Not a directory\n", c.prog, cpQ(c.targetDir, q, sizeof(q)));
            goto done;
        }
        dir = c.targetDir;
    } else {
        if (nops == 1) {
            fprintf(stderr, "%s: missing destination file operand after %s\n", c.prog, cpQ(ops[0], q, sizeof(q)));
            status = cpTry(&c);
            goto done;
        }
        if (c.noTargetDir) {
            if (nops > 2) {
                fprintf(stderr, "%s: extra operand %s\n", c.prog, cpQ(ops[2], q, sizeof(q)));
                status = cpTry(&c);
                goto done;
            }
        } else {
            struct stat st;
            const char *last = ops[nops - 1];
            bool isDir = stat(last, &st) == 0 && S_ISDIR(st.st_mode);
            if (nops > 2 && !isDir) {
                int err = stat(last, &st) != 0 ? errno : ENOTDIR;
                fprintf(stderr, "%s: target %s: %s\n", c.prog, cpQ(last, q, sizeof(q)), strerror(err));
                goto done;
            }
            if (c.parents && !isDir) {
                fprintf(stderr, "%s: with --parents, the destination must be a directory\n", c.prog);
                status = cpTry(&c);
                goto done;
            }
            if (isDir) dir = last;
        }
        nsrc = nops - 1;
    }
    if (c.parents && !dir) {
        fprintf(stderr, "%s: with --parents, the destination must be a directory\n", c.prog);
        status = cpTry(&c);
        goto done;
    }

    for (size_t k = 0; k < nsrc; k++) {
        const char *src = ops[k];
        char *dst;
        if (!dir) {
            dst = strdup(ops[nops - 1]);
        } else if (c.parents) {
            const char *rel = src;
            while (*rel == '/') rel++;
            dst = gnuPathJoin(dir, rel);
            /* Make the leading directories, copying their modes. */
            if (dst) {
                char *walk = strdup(rel);
                char *slash = walk;
                while (walk && (slash = strchr(slash, '/'))) {
                    *slash = '\0';
                    char *sd = gnuPathJoin(dir, walk);
                    struct stat ps, ds;
                    if (sd && stat(sd, &ds) != 0) {
                        char *srcPart = strndup(src, (size_t)(rel - src) + strlen(walk));
                        mode_t mode = srcPart && stat(srcPart, &ps) == 0 ? (ps.st_mode & 07777) : 0777;
                        if (mkdir(sd, mode | 0700) == 0) {
                            /* GNU prints these two unquoted. */
                            if (c.verbose) printf("%s -> %s\n", srcPart ? srcPart : walk, sd);
                            chmod(sd, c.pMode ? mode : (mode & ~c.umask));
                        }
                        free(srcPart);
                    }
                    free(sd);
                    *slash++ = '/';
                }
                free(walk);
            }
        } else {
            char *b = cpBase(src);
            dst = b ? gnuPathJoin(dir, b) : NULL;
            free(b);
        }
        if (!dst) { c.status = 1; continue; }
        if (mv) cpMove(&c, src, src, dst, dst);
        else cpCopy(&c, src, src, dst, dst, true, 0);
        free(dst);
    }
    status = c.status;

done:
    for (size_t k = 0; k < c.nlinks; k++) free(c.links[k].dst);
    free(c.links);
    free(ops);
    if (fflush(stdout) != 0) status = 1;
    return status;
}

int smallclueCpCommand(int argc, char **argv) {
    return cpMain(argc, argv, false);
}

int smallclueMvCommand(int argc, char **argv) {
    return cpMain(argc, argv, true);
}
