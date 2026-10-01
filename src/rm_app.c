/*
 * rm: remove files and directories, compatible with GNU coreutils 9.
 *
 * The rm this replaces asked "remove 'DIR'? [y/N]" before every bare
 * `rm -r DIR` as a safety net, and refused outright when stdin was not a
 * terminal ("cannot prompt on non-interactive input") -- so in any script,
 * `rm -r dir` removed nothing and failed. GNU never asks for that. It also
 * lacked -d, -v, -I and --interactive, and worded every message its own way.
 *
 * Prompts follow GNU's: -i asks for each file, naming its type ("remove
 * regular empty file", "descend into directory"); -I asks once for more than
 * three files or any recursive removal; without -f, a write-protected file
 * is asked about only when stdin is a terminal. Answers are read from stdin
 * whatever it is. Messages, refusals ('.', '..', a recursive '/') and exit
 * statuses are GNU's.
 *
 * Kept from the old rm: a hosted shell that expands patterns itself
 * (SMALLCLUE_ARGS_EXPANDED, iSH-AOK) never has rm glob again, and elsewhere a
 * name that does not exist but contains a pattern is expanded once.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "rm_app.h"
#include "gnu_util.h"

#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(PSCAL_TARGET_IOS)
#include "common/path_truncate.h"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum { RM_NEVER, RM_ONCE, RM_ALWAYS } RmInteractive;

typedef struct {
    bool force;
    RmInteractive interactive;
    bool recursive;
    bool dirs;            /* -d */
    bool verbose;
    bool preserveRoot;
    bool oneFileSystem;
    bool stdinTty;
} RmOptions;

static const char *rmFileType(const struct stat *st) {
    if (S_ISREG(st->st_mode)) return st->st_size == 0 ? "regular empty file" : "regular file";
    if (S_ISDIR(st->st_mode)) return "directory";
    if (S_ISLNK(st->st_mode)) return "symbolic link";
    if (S_ISFIFO(st->st_mode)) return "fifo";
    if (S_ISSOCK(st->st_mode)) return "socket";
    if (S_ISCHR(st->st_mode)) return "character special file";
    if (S_ISBLK(st->st_mode)) return "block special file";
    return "file";
}

static bool rmWriteProtected(const char *path, const struct stat *st) {
    if (S_ISLNK(st->st_mode)) return false;
    return access(path, W_OK) != 0 && errno == EACCES;
}

/* Should `path` be asked about, and if so, does the user agree? `descend`
 * asks about entering a directory rather than removing it. */
static bool rmAsk(const RmOptions *o, const char *path, const struct stat *st, bool descend) {
    bool protectedFile = !o->force && rmWriteProtected(path, st);
    bool ask = o->interactive == RM_ALWAYS || (protectedFile && o->stdinTty);
    if (!ask) return true;
    char q[PATH_MAX + 8];
    gnuQuote(path, q, sizeof(q));
    if (descend)
        fprintf(stderr, "rm: descend into %sdirectory %s? ", protectedFile ? "write-protected " : "", q);
    else
        fprintf(stderr, "rm: remove %s%s %s? ", protectedFile ? "write-protected " : "", rmFileType(st), q);
    fflush(stderr);
    return gnuYes();
}

static bool rmDirIsEmpty(const char *path) {
    DIR *d = opendir(path);
    if (!d) return false;
    struct dirent *e;
    bool empty = true;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            empty = false;
            break;
        }
    }
    closedir(d);
    return empty;
}

static void rmFail(const char *path, int err) {
    char q[PATH_MAX + 8];
    fprintf(stderr, "rm: cannot remove %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(err));
}

/* Removes `path`; false on any failure. A declined prompt is not a failure,
 * but it leaves *kept set so the directory above is not removed either. */
static bool rmPath(const RmOptions *o, const char *path, dev_t topDev, bool *kept) {
    char q[PATH_MAX + 8];
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (o->force && errno == ENOENT) return true;
        rmFail(path, errno);
        return false;
    }

    if (S_ISDIR(st.st_mode)) {
        if (!o->recursive && !o->dirs) {
            rmFail(path, EISDIR);
            return false;
        }
        if (!o->recursive) {
            /* -d alone: an empty directory only */
            if (!rmAsk(o, path, &st, false)) {
                *kept = true;
                return true;
            }
            if (rmdir(path) != 0) {
                rmFail(path, errno);
                return false;
            }
            if (o->verbose) printf("removed directory %s\n", gnuQuote(path, q, sizeof(q)));
            return true;
        }
        if (o->oneFileSystem && st.st_dev != topDev) {
            fprintf(stderr, "rm: skipping %s, since it's on a different device\n", gnuQuote(path, q, sizeof(q)));
            return false;
        }
        bool empty = rmDirIsEmpty(path);
        if (!empty && !rmAsk(o, path, &st, true)) {
            *kept = true;
            return true;
        }
        bool ok = true;
        bool childKept = false;
        if (!empty) {
            DIR *d = opendir(path);
            if (!d) {
                rmFail(path, errno);
                return false;
            }
            /* Names first, then removal: removing while reading a
             * directory can skip entries. */
            char **names = NULL;
            size_t n = 0, cap = 0;
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                if (n == cap) {
                    cap = cap ? cap * 2 : 16;
                    char **nn = (char **)realloc(names, cap * sizeof(char *));
                    if (!nn) break;
                    names = nn;
                }
                names[n++] = strdup(e->d_name);
            }
            closedir(d);
            for (size_t i = 0; i < n; i++) {
                char child[PATH_MAX];
                size_t plen = strlen(path);
                int w = snprintf(child, sizeof(child), "%s%s%s", path,
                                 (plen && path[plen - 1] == '/') ? "" : "/", names[i]);
                if (w < 0 || (size_t)w >= sizeof(child)) {
                    rmFail(path, ENAMETOOLONG);
                    ok = false;
                } else if (!rmPath(o, child, topDev, &childKept)) {
                    ok = false;
                }
                free(names[i]);
            }
            free(names);
        }
        if (!ok || childKept) {
            if (childKept) *kept = true;
            return ok;
        }
        if (!rmAsk(o, path, &st, false)) {
            *kept = true;
            return true;
        }
        if (rmdir(path) != 0) {
            rmFail(path, errno);
            return false;
        }
        if (o->verbose) printf("removed directory %s\n", gnuQuote(path, q, sizeof(q)));
        return true;
    }

    if (!rmAsk(o, path, &st, false)) {
        *kept = true;
        return true;
    }
    if (unlink(path) != 0) {
        rmFail(path, errno);
        return false;
    }
    if (o->verbose) printf("removed %s\n", gnuQuote(path, q, sizeof(q)));
    return true;
}

static bool rmIsDotOrDotDot(const char *path) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') len--;
    size_t start = len;
    while (start > 0 && path[start - 1] != '/') start--;
    size_t n = len - start;
    return (n == 1 && path[start] == '.') || (n == 2 && path[start] == '.' && path[start + 1] == '.');
}

static bool rmIsRoot(const char *path) {
    char resolved[PATH_MAX];
    const char *target = realpath(path, resolved) ? resolved : path;
    return strcmp(target, "/") == 0;
}

static bool rmOne(const RmOptions *o, const char *path) {
    char q[PATH_MAX + 8];
    if (o->recursive && rmIsDotOrDotDot(path)) {
        fprintf(stderr, "rm: refusing to remove '.' or '..' directory: skipping %s\n", gnuQuote(path, q, sizeof(q)));
        return false;
    }
    if (o->recursive && o->preserveRoot && rmIsRoot(path)) {
        fprintf(stderr, "rm: it is dangerous to operate recursively on '/'\n"
                        "rm: use --no-preserve-root to override this failsafe\n");
        return false;
    }
    struct stat st;
    dev_t dev = lstat(path, &st) == 0 ? st.st_dev : 0;
    bool kept = false;
    return rmPath(o, path, dev, &kept);
}

static void rmUsage(FILE *fp) {
    fputs("Usage: rm [OPTION]... [FILE]...\n"
          "Remove (unlink) the FILE(s).\n"
          "  -f, --force           ignore nonexistent files and arguments, never prompt\n"
          "  -i                    prompt before every removal\n"
          "  -I                    prompt once before removing more than three files, or\n"
          "                          when removing recursively\n"
          "      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or\n"
          "                          always (-i); without WHEN, prompt always\n"
          "      --one-file-system  when removing recursively, skip any directory that is\n"
          "                          on a file system different from that of the argument\n"
          "      --no-preserve-root  do not treat '/' specially\n"
          "      --preserve-root   do not remove '/' (default)\n"
          "  -r, -R, --recursive   remove directories and their contents recursively\n"
          "  -d, --dir             remove empty directories\n"
          "  -v, --verbose         explain what is being done\n",
          fp);
}

int smallclueRmCommand(int argc, char **argv) {
    RmOptions o;
    memset(&o, 0, sizeof(o));
    o.interactive = RM_NEVER;
    o.preserveRoot = true;
    o.stdinTty = isatty(STDIN_FILENO);
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
#define RM_LONG(n) (len == strlen(n) && !strncmp(opt, n, len))
            if (RM_LONG("force")) { o.force = true; o.interactive = RM_NEVER; }
            else if (RM_LONG("recursive")) o.recursive = true;
            else if (RM_LONG("dir")) o.dirs = true;
            else if (RM_LONG("verbose")) o.verbose = true;
            else if (RM_LONG("one-file-system")) o.oneFileSystem = true;
            else if (RM_LONG("preserve-root")) o.preserveRoot = true;
            else if (RM_LONG("no-preserve-root")) o.preserveRoot = false;
            else if (RM_LONG("interactive")) {
                if (!val || !strcmp(val, "always") || !strcmp(val, "yes")) { o.interactive = RM_ALWAYS; o.force = false; }
                else if (!strcmp(val, "once")) { o.interactive = RM_ONCE; o.force = false; }
                else if (!strcmp(val, "never") || !strcmp(val, "no") || !strcmp(val, "none")) o.interactive = RM_NEVER;
                else {
                    char qa[512], qb[64], q1[32], q2[32], q3[32], q4[32], q5[32], q6[32];
                    fprintf(stderr, "rm: invalid argument %s for %s\n"
                                    "Valid arguments are:\n"
                                    "  - %s, %s, %s\n"
                                    "  - %s\n"
                                    "  - %s, %s\n"
                                    "Try 'rm --help' for more information.\n",
                            gnuQuoteLocale(val, qa, sizeof(qa)), gnuQuoteLocale("--interactive", qb, sizeof(qb)),
                            gnuQuoteLocale("never", q1, sizeof(q1)), gnuQuoteLocale("no", q2, sizeof(q2)),
                            gnuQuoteLocale("none", q3, sizeof(q3)), gnuQuoteLocale("once", q4, sizeof(q4)),
                            gnuQuoteLocale("always", q5, sizeof(q5)), gnuQuoteLocale("yes", q6, sizeof(q6)));
                    status = 1;
                    goto done;
                }
            } else if (RM_LONG("help")) {
                rmUsage(stdout);
                goto done;
            } else if (RM_LONG("version")) {
                puts("rm (SmallCLUE) 9.4 -- a GNU rm compatible implementation");
                goto done;
            } else {
                fprintf(stderr, "rm: unrecognized option '%s'\nTry 'rm --help' for more information.\n", arg);
                status = 1;
                goto done;
            }
#undef RM_LONG
            continue;
        }
        for (const char *c = arg + 1; *c; c++) {
            switch (*c) {
                case 'f': o.force = true; o.interactive = RM_NEVER; break;
                case 'i': o.interactive = RM_ALWAYS; o.force = false; break;
                case 'I': o.interactive = RM_ONCE; o.force = false; break;
                case 'r': case 'R': o.recursive = true; break;
                case 'd': o.dirs = true; break;
                case 'v': o.verbose = true; break;
                default:
                    fprintf(stderr, "rm: invalid option -- '%c'\nTry 'rm --help' for more information.\n", *c);
                    status = 1;
                    goto done;
            }
        }
    }

    if (nfiles == 0) {
        if (!o.force) {
            fprintf(stderr, "rm: missing operand\nTry 'rm --help' for more information.\n");
            status = 1;
        }
        goto done;
    }

    if (o.interactive == RM_ONCE && (o.recursive || nfiles > 3)) {
        if (o.recursive)
            fprintf(stderr, "rm: remove %d argument%s recursively? ", nfiles, nfiles == 1 ? "" : "s");
        else
            fprintf(stderr, "rm: remove %d arguments? ", nfiles);
        fflush(stderr);
        if (!gnuYes()) goto done;
    }

    for (int i = 0; i < nfiles; i++) {
        const char *path = files[i];
#if defined(PSCAL_TARGET_IOS)
        char expandedBuf[PATH_MAX];
        if (pathTruncateExpand(path, expandedBuf, sizeof(expandedBuf))) path = expandedBuf;
#endif
#if !defined(SMALLCLUE_ARGS_EXPANDED)
        /* A host whose shell does not expand patterns (PSCAL's): a name that
         * does not exist but holds one is expanded here, once. */
        struct stat st;
        if (lstat(path, &st) != 0 && strpbrk(path, "*?[")) {
            glob_t g;
            memset(&g, 0, sizeof(g));
            if (glob(path, 0, NULL, &g) == 0) {
                for (size_t m = 0; m < g.gl_pathc; m++)
                    if (!rmOne(&o, g.gl_pathv[m])) status = 1;
                globfree(&g);
                continue;
            }
            globfree(&g);
        }
#endif
        if (!rmOne(&o, path)) status = 1;
    }

done:
    fflush(stdout);
    free(files);
    return status;
}
