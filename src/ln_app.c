/*
 * ln: make links between files, compatible with GNU coreutils 9.
 *
 * The ln this replaces took -s and -f and nothing else, so `ln -sfn` -- the
 * usual way to repoint a symlink to a directory -- failed with "illegal option
 * -- n" wherever SmallCLUE's applets shadow the distro's (iSH-AOK's
 * native-links.sh), and a script that hid the error carried on without its
 * link.
 *
 * All four forms (TARGET LINK_NAME; TARGET; TARGET... DIRECTORY; -t DIRECTORY
 * TARGET...) and GNU's options: -b/--backup[=CONTROL], -S/--suffix, -d/-F,
 * -f, -i, -L, -n, -P, -r, -s, -t, -T, -v. A destination replaced under -f is
 * replaced atomically, as GNU does: the new link is made under a temporary
 * name beside it and renamed over it. Messages and exit statuses are GNU's.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "ln_app.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum { LN_BACKUP_NONE, LN_BACKUP_SIMPLE, LN_BACKUP_NUMBERED, LN_BACKUP_EXISTING } LnBackup;

typedef struct {
    bool symbolic;
    bool force;
    bool interactive;
    bool verbose;
    bool relative;
    bool logical;
    bool noDereference;   /* -n: a symlink to a directory is not a directory */
    bool hardDirs;        /* -d/-F */
    LnBackup backup;
    const char *suffix;
    int status;
} LnOptions;

/* ------------------------------------------------------------------------ */
/* GNU's quoting (quoteaf, shell-escape-always style)                       */

static const char *lnQuote(const char *s, char *buf, size_t size) {
    bool needDouble = strchr(s, '\'') != NULL;
    bool doubleOk = needDouble && !strpbrk(s, "\"$`\\!");
    size_t o = 0;
#define LN_PUT(c) do { if (o + 1 < size) buf[o++] = (c); } while (0)
    if (doubleOk) {
        LN_PUT('"');
        for (const char *p = s; *p; p++) LN_PUT(*p);
        LN_PUT('"');
    } else {
        LN_PUT('\'');
        for (const char *p = s; *p; p++) {
            if (*p == '\'') {
                LN_PUT('\''); LN_PUT('\\'); LN_PUT('\''); LN_PUT('\'');
            } else {
                LN_PUT(*p);
            }
        }
        LN_PUT('\'');
    }
#undef LN_PUT
    buf[o] = '\0';
    return buf;
}

/* quotef: bare unless the name needs quoting for a shell. */
static const char *lnQuoteMaybe(const char *s, char *buf, size_t size) {
    bool plain = *s != '\0';
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || strchr("+-./:=@_%^,", c) || c >= 0x80)) {
            plain = false;
            break;
        }
    }
    if (!plain) return lnQuote(s, buf, size);
    snprintf(buf, size, "%s", s);
    return buf;
}

/* ------------------------------------------------------------------------ */
/* Paths                                                                     */

/* The last component, without trailing slashes ("a/b/" -> "b"). */
static void lnBaseName(const char *path, char *out, size_t size) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && path[start - 1] != '/') start--;
    size_t n = len - start;
    if (n >= size) n = size - 1;
    memcpy(out, path + start, n);
    out[n] = '\0';
}

static bool lnJoin(char *out, size_t size, const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    bool slash = dlen > 0 && dir[dlen - 1] == '/';
    int n = snprintf(out, size, "%s%s%s", dir, slash ? "" : "/", name);
    return n >= 0 && (size_t)n < size;
}

/* Lexical normalisation of an absolute path: "." and ".." and repeated
 * slashes, without touching the filesystem. */
static void lnNormalize(char *path) {
    char *parts[PATH_MAX / 2];
    int n = 0;
    char *save = NULL;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *t = strtok_r(tmp, "/", &save); t; t = strtok_r(NULL, "/", &save)) {
        if (!strcmp(t, ".")) continue;
        if (!strcmp(t, "..")) {
            if (n > 0) n--;
            continue;
        }
        parts[n++] = t;
    }
    char out[PATH_MAX];
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        int w = snprintf(out + o, sizeof(out) - o, "/%s", parts[i]);
        if (w < 0) break;
        o += (size_t)w;
        if (o >= sizeof(out)) break;
    }
    if (n == 0) snprintf(out, sizeof(out), "/");
    snprintf(path, PATH_MAX, "%s", out);
}

/* An absolute, canonical form of `path` that may not exist yet: the longest
 * existing prefix is resolved (symlinks included), the rest is appended. */
static bool lnCanonicalMissing(const char *path, char *out) {
    char abs[PATH_MAX];
    if (path[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", path);
    } else {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return false;
        if (!lnJoin(abs, sizeof(abs), cwd, path)) return false;
    }
    lnNormalize(abs);
    char head[PATH_MAX];
    snprintf(head, sizeof(head), "%s", abs);
    char tail[PATH_MAX] = "";
    for (;;) {
        char resolved[PATH_MAX];
        if (realpath(head, resolved)) {
            int n = snprintf(out, PATH_MAX, "%s%s%s", resolved,
                             (tail[0] && strcmp(resolved, "/")) ? "/" : "", tail);
            if (n < 0 || n >= PATH_MAX) return false;
            lnNormalize(out);
            return true;
        }
        char *slash = strrchr(head, '/');
        if (!slash) return false;
        char newTail[PATH_MAX];
        snprintf(newTail, sizeof(newTail), "%s%s%s", slash + 1, tail[0] ? "/" : "", tail);
        snprintf(tail, sizeof(tail), "%s", newTail);
        if (slash == head) {
            head[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
}

/* -r: `target` as seen from the directory the link `linkPath` lives in. */
static bool lnRelative(const char *target, const char *linkPath, char *out, size_t size) {
    char t[PATH_MAX], l[PATH_MAX];
    if (!lnCanonicalMissing(target, t)) return false;
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", linkPath);
    size_t len = strlen(dir);
    while (len > 1 && dir[len - 1] == '/') dir[--len] = '\0';
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) dir[1] = '\0';
        else *slash = '\0';
    } else {
        snprintf(dir, sizeof(dir), ".");
    }
    if (!lnCanonicalMissing(dir, l)) return false;
    /* common prefix by components */
    size_t i = 0, lastSep = 0;
    while (t[i] && l[i] && t[i] == l[i]) {
        if (t[i] == '/') lastSep = i;
        i++;
    }
    if ((t[i] == '\0' || t[i] == '/') && (l[i] == '\0' || l[i] == '/')) lastSep = i;
    if (!strcmp(l, "/")) lastSep = 0;
    size_t o = 0;
    out[0] = '\0';
    const char *rest = l + lastSep;
    for (const char *p = rest; *p; p++) {
        if (*p == '/' && p[1] != '\0') {
            int w = snprintf(out + o, size - o, "%s..", o ? "/" : "");
            if (w < 0 || (size_t)w >= size - o) return false;
            o += (size_t)w;
        }
    }
    const char *down = t + lastSep;
    if (*down == '/') down++;
    if (*down) {
        int w = snprintf(out + o, size - o, "%s%s", o ? "/" : "", down);
        if (w < 0 || (size_t)w >= size - o) return false;
        o += (size_t)w;
    }
    if (o == 0) snprintf(out, size, ".");
    return true;
}

/* ------------------------------------------------------------------------ */
/* Backups                                                                   */

static LnBackup lnBackupFromString(const char *s, bool *ok) {
    *ok = true;
    if (!s || !*s) return LN_BACKUP_EXISTING;
    if (!strcmp(s, "none") || !strcmp(s, "off")) return LN_BACKUP_NONE;
    if (!strcmp(s, "simple") || !strcmp(s, "never")) return LN_BACKUP_SIMPLE;
    if (!strcmp(s, "numbered") || !strcmp(s, "t")) return LN_BACKUP_NUMBERED;
    if (!strcmp(s, "existing") || !strcmp(s, "nil")) return LN_BACKUP_EXISTING;
    *ok = false;
    return LN_BACKUP_NONE;
}

/* The highest N of an existing NAME.~N~ beside `path`, or 0. */
static long lnHighestNumbered(const char *path) {
    char base[PATH_MAX];
    lnBaseName(path, base, sizeof(base));
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) dir[1] = '\0';
        else *slash = '\0';
    } else {
        snprintf(dir, sizeof(dir), ".");
    }
    DIR *d = opendir(dir);
    if (!d) return 0;
    long highest = 0;
    size_t blen = strlen(base);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strncmp(n, base, blen) != 0 || strncmp(n + blen, ".~", 2) != 0) continue;
        const char *num = n + blen + 2;
        char *end = NULL;
        long v = strtol(num, &end, 10);
        if (end && end != num && end[0] == '~' && end[1] == '\0' && v > highest) highest = v;
    }
    closedir(d);
    return highest;
}

static bool lnBackupName(const LnOptions *o, const char *path, char *out, size_t size) {
    LnBackup kind = o->backup;
    long highest = 0;
    if (kind == LN_BACKUP_NUMBERED || kind == LN_BACKUP_EXISTING) {
        highest = lnHighestNumbered(path);
        if (kind == LN_BACKUP_EXISTING) kind = highest > 0 ? LN_BACKUP_NUMBERED : LN_BACKUP_SIMPLE;
    }
    int n;
    if (kind == LN_BACKUP_NUMBERED)
        n = snprintf(out, size, "%s.~%ld~", path, highest + 1);
    else
        n = snprintf(out, size, "%s%s", path, o->suffix);
    return n >= 0 && (size_t)n < size;
}

/* ------------------------------------------------------------------------ */
/* Making one link                                                           */

static bool lnYes(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return false;
    return line[0] == 'y' || line[0] == 'Y';
}

/* Creates the link itself at `at`: symlink(target) or link(source). */
static int lnMake(const LnOptions *o, const char *target, const char *at) {
    if (o->symbolic) return symlink(target, at);
    if (o->logical) return linkat(AT_FDCWD, target, AT_FDCWD, at, AT_SYMLINK_FOLLOW);
    return link(target, at);
}

/* A temporary name beside `dest`, for an atomic replace. */
static bool lnTempName(const char *dest, char *out, size_t size, unsigned salt) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", dest);
    char *slash = strrchr(dir, '/');
    if (slash) slash[1] = '\0';
    else dir[0] = '\0';
    int n = snprintf(out, size, "%sCuXXXX%04x%04x", dir, (unsigned)getpid() & 0xffff, salt & 0xffff);
    return n >= 0 && (size_t)n < size;
}

static void lnFailLink(const LnOptions *o, const char *dest, const char *source, int err) {
    char q1[PATH_MAX + 8], q2[PATH_MAX + 8];
    lnQuote(dest, q1, sizeof(q1));
    lnQuote(source, q2, sizeof(q2));
    if (o->symbolic) {
        if (err != ENAMETOOLONG && *source)
            fprintf(stderr, "ln: failed to create symbolic link %s: %s\n", q1, strerror(err));
        else
            fprintf(stderr, "ln: failed to create symbolic link %s -> %s: %s\n", q1, q2, strerror(err));
    } else if (err == EMLINK) {
        fprintf(stderr, "ln: failed to create hard link to %s: %s\n", q2, strerror(err));
    } else if (err == EDQUOT || err == EEXIST || err == ENOSPC || err == EROFS) {
        fprintf(stderr, "ln: failed to create hard link %s: %s\n", q1, strerror(err));
    } else {
        fprintf(stderr, "ln: failed to create hard link %s => %s: %s\n", q1, q2, strerror(err));
    }
}

/* The directory part of a path, for comparing two names' directories. */
static void lnDirName(const char *path, char *out, size_t size) {
    snprintf(out, size, "%s", path);
    size_t len = strlen(out);
    while (len > 1 && out[len - 1] == '/') out[--len] = '\0';
    char *slash = strrchr(out, '/');
    if (!slash) snprintf(out, size, ".");
    else if (slash == out) out[1] = '\0';
    else *slash = '\0';
}

/* GNU's same_name: do the two names denote the same directory entry? */
static bool lnSameName(const char *a, const char *b) {
    char ba[PATH_MAX], bb[PATH_MAX];
    lnBaseName(a, ba, sizeof(ba));
    lnBaseName(b, bb, sizeof(bb));
    if (strcmp(ba, bb) != 0) return false;
    char da[PATH_MAX], db[PATH_MAX];
    lnDirName(a, da, sizeof(da));
    lnDirName(b, db, sizeof(db));
    struct stat sa, sb;
    return stat(da, &sa) == 0 && stat(db, &sb) == 0 && sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static bool lnDoLink(LnOptions *o, const char *source, const char *dest) {
    char q1[PATH_MAX + 8], q2[PATH_MAX + 8];
    struct stat sourceStat;
    bool haveSource = false;

    if (!o->symbolic) {
        int r = o->logical ? stat(source, &sourceStat) : lstat(source, &sourceStat);
        if (r != 0) {
            fprintf(stderr, "ln: failed to access %s: %s\n", lnQuote(source, q1, sizeof(q1)), strerror(errno));
            return false;
        }
        haveSource = true;
        if (S_ISDIR(sourceStat.st_mode) && !o->hardDirs) {
            fprintf(stderr, "ln: %s: hard link not allowed for directory\n", lnQuoteMaybe(source, q1, sizeof(q1)));
            return false;
        }
    }

    char relBuf[PATH_MAX];
    const char *target = source;
    if (o->symbolic && o->relative) {
        if (lnRelative(source, dest, relBuf, sizeof(relBuf))) target = relBuf;
    }

    if (lnMake(o, target, dest) == 0) {
        if (o->verbose)
            printf("%s %c> %s\n", lnQuote(dest, q1, sizeof(q1)), o->symbolic ? '-' : '=',
                   lnQuote(target, q2, sizeof(q2)));
        return true;
    }
    int err = errno;
    if (err != EEXIST || !(o->force || o->interactive || o->backup != LN_BACKUP_NONE)) {
        lnFailLink(o, dest, source, err);
        return false;
    }

    struct stat destStat;
    if (lstat(dest, &destStat) != 0) {
        lnFailLink(o, dest, source, err);
        return false;
    }
    if (S_ISDIR(destStat.st_mode)) {
        fprintf(stderr, "ln: %s: cannot overwrite directory\n", lnQuoteMaybe(dest, q1, sizeof(q1)));
        return false;
    }
    /* GNU's rule: a hard link onto its own source is refused always; a
     * symlink named after its own target only without a backup, since the
     * backup moves the original aside first. */
    bool same = o->symbolic
        ? (o->backup == LN_BACKUP_NONE && lnSameName(source, dest))
        : (haveSource && sourceStat.st_dev == destStat.st_dev && sourceStat.st_ino == destStat.st_ino);
    if (same) {
        fprintf(stderr, "ln: %s and %s are the same file\n", lnQuote(source, q1, sizeof(q1)),
                lnQuote(dest, q2, sizeof(q2)));
        return false;
    }
    if (o->interactive) {
        fprintf(stderr, "ln: replace %s? ", lnQuote(dest, q1, sizeof(q1)));
        fflush(stderr);
        if (!lnYes()) return false;
    }

    char backup[PATH_MAX];
    bool backedUp = false;
    if (o->backup != LN_BACKUP_NONE) {
        if (!lnBackupName(o, dest, backup, sizeof(backup))) {
            fprintf(stderr, "ln: %s: %s\n", lnQuote(dest, q1, sizeof(q1)), strerror(ENAMETOOLONG));
            return false;
        }
        if (rename(dest, backup) != 0) {
            fprintf(stderr, "ln: cannot backup %s: %s\n", lnQuote(dest, q1, sizeof(q1)), strerror(errno));
            return false;
        }
        backedUp = true;
        if (lnMake(o, target, dest) != 0) {
            int e = errno;
            rename(backup, dest);
            lnFailLink(o, dest, source, e);
            return false;
        }
    } else {
        /* Atomic replace: the new link under a temporary name, renamed over
         * the old one, so there is never a moment without `dest`. */
        char tmp[PATH_MAX];
        bool made = false;
        for (unsigned salt = 0; salt < 64 && !made; salt++) {
            if (!lnTempName(dest, tmp, sizeof(tmp), salt)) break;
            if (lnMake(o, target, tmp) == 0) made = true;
            else if (errno != EEXIST) break;
        }
        if (!made) {
            /* Not possible in that directory: remove, then make. */
            if (unlink(dest) != 0 || lnMake(o, target, dest) != 0) {
                lnFailLink(o, dest, source, errno);
                return false;
            }
        } else if (rename(tmp, dest) != 0) {
            int e = errno;
            unlink(tmp);
            lnFailLink(o, dest, source, e);
            return false;
        }
    }
    if (o->verbose) {
        if (backedUp) printf("%s ~ ", lnQuote(backup, q1, sizeof(q1)));
        printf("%s %c> %s\n", lnQuote(dest, q1, sizeof(q1)), o->symbolic ? '-' : '=',
               lnQuote(target, q2, sizeof(q2)));
    }
    return true;
}

/* GNU's target_directory_operand: does the last operand name a directory to
 * put links in? With -n a symlink to a directory does not count. */
static bool lnTargetIsDirectory(const LnOptions *o, const char *file, int *errOut) {
    struct stat st;
    int r = o->noDereference ? lstat(file, &st) : stat(file, &st);
    *errOut = r == 0 ? (S_ISDIR(st.st_mode) ? 0 : ENOTDIR) : errno;
    return r == 0 && S_ISDIR(st.st_mode);
}

static void lnUsage(FILE *fp) {
    fputs("Usage: ln [OPTION]... [-T] TARGET LINK_NAME\n"
          "  or:  ln [OPTION]... TARGET\n"
          "  or:  ln [OPTION]... TARGET... DIRECTORY\n"
          "  or:  ln [OPTION]... -t DIRECTORY TARGET...\n"
          "      --backup[=CONTROL]      make a backup of each existing destination file\n"
          "  -b                          like --backup but does not accept an argument\n"
          "  -d, -F, --directory         allow hard links to directories\n"
          "  -f, --force                 remove existing destination files\n"
          "  -i, --interactive           prompt whether to remove destinations\n"
          "  -L, --logical               dereference TARGETs that are symbolic links\n"
          "  -n, --no-dereference        treat LINK_NAME as a normal file if\n"
          "                                it is a symbolic link to a directory\n"
          "  -P, --physical              make hard links directly to symbolic links\n"
          "  -r, --relative              with -s, create links relative to link location\n"
          "  -s, --symbolic              make symbolic links instead of hard links\n"
          "  -S, --suffix=SUFFIX         override the usual backup suffix\n"
          "  -t, --target-directory=DIRECTORY  specify the DIRECTORY to create the links\n"
          "  -T, --no-target-directory   treat LINK_NAME as a normal file always\n"
          "  -v, --verbose               print name of each linked file\n",
          fp);
}

static int lnTry(void) {
    fprintf(stderr, "Try 'ln --help' for more information.\n");
    return 1;
}

int smallclueLnCommand(int argc, char **argv) {
    LnOptions o;
    memset(&o, 0, sizeof(o));
    o.backup = LN_BACKUP_NONE;
    const char *suffix = NULL;
    const char *targetDir = NULL;
    bool noTargetDir = false;
    bool wantBackup = false;
    const char *backupControl = NULL;
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nfiles = 0;
    int status = 0;
    if (!files) return 1;

    bool endOfOptions = false;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            files[nfiles++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) {
            endOfOptions = true;
            continue;
        }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *val = strchr(opt, '=');
            size_t len = val ? (size_t)(val - opt) : strlen(opt);
            if (val) val++;
#define LN_LONG(n) (len == strlen(n) && !strncmp(opt, n, len))
            if (LN_LONG("backup")) { wantBackup = true; backupControl = val; }
            else if (LN_LONG("directory")) o.hardDirs = true;
            else if (LN_LONG("force")) { o.force = true; o.interactive = false; }
            else if (LN_LONG("interactive")) { o.interactive = true; o.force = false; }
            else if (LN_LONG("logical")) o.logical = true;
            else if (LN_LONG("no-dereference")) o.noDereference = true;
            else if (LN_LONG("physical")) o.logical = false;
            else if (LN_LONG("relative")) o.relative = true;
            else if (LN_LONG("symbolic")) o.symbolic = true;
            else if (LN_LONG("verbose")) o.verbose = true;
            else if (LN_LONG("no-target-directory")) noTargetDir = true;
            else if (LN_LONG("suffix") || LN_LONG("target-directory")) {
                if (!val) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "ln: option '--%.*s' requires an argument\n", (int)len, opt);
                        status = lnTry();
                        goto done;
                    }
                    val = argv[++i];
                }
                if (LN_LONG("suffix")) { suffix = val; wantBackup = true; }
                else targetDir = val;
            } else if (LN_LONG("help")) {
                lnUsage(stdout);
                goto done;
            } else if (LN_LONG("version")) {
                puts("ln (SmallCLUE) 9.4 -- a GNU ln compatible implementation");
                goto done;
            } else {
                fprintf(stderr, "ln: unrecognized option '%s'\n", arg);
                status = lnTry();
                goto done;
            }
#undef LN_LONG
            continue;
        }
        for (char *c = arg + 1; *c; c++) {
            switch (*c) {
                case 'b': wantBackup = true; break;
                case 'd': case 'F': o.hardDirs = true; break;
                case 'f': o.force = true; o.interactive = false; break;
                case 'i': o.interactive = true; o.force = false; break;
                case 'L': o.logical = true; break;
                case 'n': o.noDereference = true; break;
                case 'P': o.logical = false; break;
                case 'r': o.relative = true; break;
                case 's': o.symbolic = true; break;
                case 'T': noTargetDir = true; break;
                case 'v': o.verbose = true; break;
                case 'S': case 't': {
                    char opt = *c;
                    const char *val = c[1] ? c + 1 : NULL;
                    if (!val) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "ln: option requires an argument -- '%c'\n", opt);
                            status = lnTry();
                            goto done;
                        }
                        val = argv[++i];
                    }
                    if (opt == 'S') { suffix = val; wantBackup = true; }
                    else targetDir = val;
                    c += strlen(c) - 1;
                    break;
                }
                default:
                    fprintf(stderr, "ln: invalid option -- '%c'\n", *c);
                    status = lnTry();
                    goto done;
            }
        }
    }

    if (o.relative && !o.symbolic) {
        fprintf(stderr, "ln: cannot do --relative without --symbolic\n");
        status = 1;
        goto done;
    }
    if (wantBackup) {
        bool ok;
        const char *control = backupControl ? backupControl : getenv("VERSION_CONTROL");
        o.backup = lnBackupFromString(control, &ok);
        if (!ok) {
            fprintf(stderr, "ln: invalid argument '%s' for 'backup type'\n"
                            "Valid arguments are:\n"
                            "  - 'none', 'off'\n"
                            "  - 'simple', 'never'\n"
                            "  - 'existing', 'nil'\n"
                            "  - 'numbered', 't'\n", control);
            status = lnTry();
            goto done;
        }
    }
    o.suffix = suffix ? suffix : (getenv("SIMPLE_BACKUP_SUFFIX") ? getenv("SIMPLE_BACKUP_SUFFIX") : "~");

    char q[PATH_MAX + 8];
    if (nfiles <= 0) {
        fprintf(stderr, "ln: missing file operand\n");
        status = lnTry();
        goto done;
    }
    if (noTargetDir) {
        if (targetDir) {
            fprintf(stderr, "ln: cannot combine --target-directory and --no-target-directory\n");
            status = 1;
            goto done;
        }
        if (nfiles != 2) {
            if (nfiles < 2)
                fprintf(stderr, "ln: missing destination file operand after %s\n", lnQuote(files[0], q, sizeof(q)));
            else
                fprintf(stderr, "ln: extra operand %s\n", lnQuote(files[2], q, sizeof(q)));
            status = lnTry();
            goto done;
        }
    } else if (targetDir) {
        struct stat st;
        if (stat(targetDir, &st) != 0) {
            fprintf(stderr, "ln: failed to access %s: %s\n", lnQuote(targetDir, q, sizeof(q)), strerror(errno));
            status = 1;
            goto done;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "ln: target %s is not a directory\n", lnQuote(targetDir, q, sizeof(q)));
            status = 1;
            goto done;
        }
    } else if (nfiles < 2) {
        targetDir = ".";
    } else {
        int err = 0;
        if (lnTargetIsDirectory(&o, files[nfiles - 1], &err)) {
            targetDir = files[--nfiles];
        } else if (nfiles > 2) {
            fprintf(stderr, "ln: target %s: %s\n", lnQuote(files[nfiles - 1], q, sizeof(q)), strerror(err));
            status = 1;
            goto done;
        }
    }

    if (targetDir) {
        for (int i = 0; i < nfiles; i++) {
            char base[PATH_MAX];
            lnBaseName(files[i], base, sizeof(base));
            char dest[PATH_MAX];
            if (!lnJoin(dest, sizeof(dest), targetDir, base)) {
                fprintf(stderr, "ln: %s: %s\n", lnQuote(files[i], q, sizeof(q)), strerror(ENAMETOOLONG));
                status = 1;
                continue;
            }
            if (!lnDoLink(&o, files[i], dest)) status = 1;
        }
    } else {
        if (!lnDoLink(&o, files[0], files[1])) status = 1;
    }

done:
    fflush(stdout);
    free(files);
    return status;
}
