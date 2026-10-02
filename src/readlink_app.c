/*
 * readlink and realpath: GNU coreutils 9 compatible, over one port of
 * gnulib's canonicalize_filename_mode -- the three existence modes (-e,
 * the default all-but-last, -m), symlinks expanded as they are met (a
 * dangling link resolves to its target), a trailing "/" or "/.." demanding
 * a directory, ELOOP after 40 links, and the no-symlinks (-s) and logical
 * (-L: ".." first, then links) passes. realpath adds --relative-to and
 * --relative-base with GNU's relpath and prefix rules.
 */

#include "readlink_app.h"

#include "gnu_getopt.h"
#include "gnu_util.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { CAN_EXISTING, CAN_ALL_BUT_LAST, CAN_MISSING };

/* gnulib's suffix_requires_dir_check: a trailing "/", "/." or a "/.." anywhere. */
static bool rlSuffixNeedsDir(const char *end) {
    while (*end == '/') {
        do end++; while (*end == '/');
        switch (*end++) {
        default: return false;
        case '\0': return true;
        case '.': break;
        }
        if (!*end || (*end == '.' && (!end[1] || end[1] == '/'))) return true;
    }
    return false;
}

static void rlDropLast(GnuBuf *r) {
    while (r->n > 1 && r->s[r->n - 1] != '/') r->n--;
    if (r->n > 1) r->n--;
    r->s[r->n] = '\0';
}

/* The canonical name, malloc'd; NULL with errno set. */
static char *rlCanon(const char *name, int mode, bool nolinks) {
    if (!*name) {
        errno = ENOENT;
        return NULL;
    }
    GnuBuf r = {0};
    if (name[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) return NULL;
        gnuBufPut(&r, cwd, strlen(cwd));
    } else {
        gnuBufPut(&r, "/", 1);
    }
    char *work = strdup(name);
    if (!work) {
        free(r.s);
        return NULL;
    }
    int links = 0;
    const char *start = work;
    while (*start) {
        while (*start == '/') start++;
        const char *end = start;
        while (*end && *end != '/') end++;
        size_t clen = (size_t)(end - start);
        if (clen == 0) break;
        if (clen == 1 && start[0] == '.') {
            start = end;
            continue;
        }
        if (clen == 2 && start[0] == '.' && start[1] == '.') {
            rlDropLast(&r);
            start = end;
            continue;
        }
        size_t before = r.n;
        if (r.s[r.n - 1] != '/') gnuBufPut(&r, "/", 1);
        gnuBufPut(&r, start, clen);
        bool last = true;
        for (const char *p = end; *p; p++)
            if (*p != '/') {
                last = false;
                break;
            }
        if (!nolinks) {
            char target[PATH_MAX];
            ssize_t n = readlink(r.s, target, sizeof(target) - 1);
            if (n >= 0) {
                if (++links > 40) {
                    if (mode == CAN_MISSING) {
                        start = end;
                        continue;
                    }
                    errno = ELOOP;
                    goto fail;
                }
                target[n] = '\0';
                /* the link's text, then what was left of the name */
                size_t rest = strlen(end);
                char *next = (char *)malloc((size_t)n + rest + 1);
                if (!next) goto fail;
                memcpy(next, target, (size_t)n);
                memcpy(next + n, end, rest + 1);
                free(work);
                work = next;
                start = work;
                if (target[0] == '/') {
                    r.n = 1;
                    r.s[1] = '\0';
                } else {
                    r.n = before;
                    r.s[r.n] = '\0';
                }
                continue;
            }
        }
        /* gnulib: a "/"-suffixed name must be a directory; otherwise a
         * physical step needs only that it was not a link (EINVAL), and a
         * logical one checks nothing until the last name */
        bool ok;
        struct stat st;
        if (rlSuffixNeedsDir(end)) {
            ok = stat(r.s, &st) == 0;
            if (ok && !S_ISDIR(st.st_mode)) {
                ok = false;
                errno = ENOTDIR;
            }
        } else if (!nolinks) {
            ok = errno == EINVAL;
        } else {
            ok = *end || access(r.s, F_OK) == 0;
        }
        if (!ok && !(mode == CAN_MISSING || (mode == CAN_ALL_BUT_LAST && errno == ENOENT && last))) goto fail;
        start = end;
    }
    free(work);
    return r.s;
fail: {
    int e = errno;
    free(work);
    free(r.s);
    errno = e;
    return NULL;
}
}

/* realpath -L: ".." textually first, then the links. */
static char *rlRealpathCanon(const char *name, int mode, bool nolinks, bool logical) {
    char *c = rlCanon(name, mode, nolinks);
    if (logical && c) {
        char *d = rlCanon(c, mode, false);
        free(c);
        return d;
    }
    return c;
}

static int rlTry(const char *prog) {
    fprintf(stderr, "Try '%s --help' for more information.\n", prog);
    return 1;
}

static const GnuLongOpt readlinkLongs[] = {
    {"canonicalize", GNU_NO_ARG, 'f'}, {"canonicalize-existing", GNU_NO_ARG, 'e'},
    {"canonicalize-missing", GNU_NO_ARG, 'm'}, {"no-newline", GNU_NO_ARG, 'n'},
    {"quiet", GNU_NO_ARG, 'q'}, {"silent", GNU_NO_ARG, 's'}, {"verbose", GNU_NO_ARG, 'v'},
    {"zero", GNU_NO_ARG, 'z'}, {"help", GNU_NO_ARG, 1}, {"version", GNU_NO_ARG, 2},
};

int smallclueReadlinkCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "readlink", "efmnqsvz", readlinkLongs,
                  sizeof(readlinkLongs) / sizeof(readlinkLongs[0]));
    int mode = -1, c, status = 1;
    bool noNewline = false, verbose = false;
    char delim = '\n', q[PATH_MAX + 64];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'e': mode = CAN_EXISTING; break;
        case 'f': mode = CAN_ALL_BUT_LAST; break;
        case 'm': mode = CAN_MISSING; break;
        case 'n': noNewline = true; break;
        case 'q': case 's': verbose = false; break;
        case 'v': verbose = true; break;
        case 'z': delim = '\0'; break;
        case 1:
            fputs("Usage: readlink [OPTION]... FILE...\n"
                  "Print value of a symbolic link or canonical file name\n\n"
                  "  -f, --canonicalize            canonicalize by following every symlink in\n"
                  "                                every component of the given name recursively;\n"
                  "                                all but the last component must exist\n"
                  "  -e, --canonicalize-existing   canonicalize by following every symlink in\n"
                  "                                every component of the given name recursively,\n"
                  "                                all components must exist\n"
                  "  -m, --canonicalize-missing    canonicalize by following every symlink in\n"
                  "                                every component of the given name recursively,\n"
                  "                                without requirements on components existence\n"
                  "  -n, --no-newline              do not output the trailing delimiter\n"
                  "  -q, --quiet\n"
                  "  -s, --silent                  suppress most error messages (on by default)\n"
                  "  -v, --verbose                 report error messages\n"
                  "  -z, --zero                    end each output line with NUL, not newline\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            status = 0;
            goto done;
        case 2: puts("readlink (SmallCLUE) 9.4"); status = 0; goto done;
        default: status = rlTry("readlink"); goto done;
        }
    }
    if (g.nops == 0) {
        fputs("readlink: missing operand\n", stderr);
        status = rlTry("readlink");
        goto done;
    }
    if (noNewline && g.nops > 1) {
        noNewline = false;
        fputs("readlink: ignoring --no-newline with multiple arguments\n", stderr);
    }
    status = 0;
    for (int i = 0; i < g.nops; i++) {
        const char *name = g.ops[i];
        char *value = NULL;
        if (mode >= 0) {
            value = rlCanon(name, mode, false);
        } else {
            char target[PATH_MAX];
            ssize_t n = readlink(name, target, sizeof(target) - 1);
            if (n >= 0) {
                target[n] = '\0';
                value = strdup(target);
            }
        }
        if (value) {
            fputs(value, stdout);
            if (!noNewline) putchar(delim);
            free(value);
        } else {
            status = 1;
            if (verbose) fprintf(stderr, "readlink: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
        }
    }
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("readlink", errno);
        status = 1;
    }
    return status;
}

/* path_prefix: `path` is `prefix` or below it. */
static bool rlPrefix(const char *prefix, const char *path) {
    if (!strcmp(prefix, "/")) return path[0] == '/';
    size_t n = strlen(prefix);
    return !strncmp(prefix, path, n) && (path[n] == '\0' || path[n] == '/');
}

/* path_common_prefix: where the two canonical names' shared directories end. */
static size_t rlCommon(const char *a, const char *b) {
    size_t i = 0, ret = 0;
    if ((a[1] == '/') != (b[1] == '/')) return 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) break;
        if (a[i] == '/') ret = i + 1;
        i++;
    }
    if ((!a[i] && !b[i]) || (!a[i] && b[i] == '/') || (!b[i] && a[i] == '/')) ret = i;
    return ret;
}

/* relpath: `name` relative to `dir`; false to print it absolute. */
static bool rlRelpath(const char *name, const char *dir) {
    size_t common = rlCommon(dir, name);
    if (!common) return false;
    const char *rs = dir + common, *fs = name + common;
    if (*rs == '/') rs++;
    if (*fs == '/') fs++;
    if (*rs) {
        fputs("..", stdout);
        for (; *rs; rs++)
            if (*rs == '/') fputs("/..", stdout);
        if (*fs) {
            putchar('/');
            fputs(fs, stdout);
        }
    } else {
        fputs(*fs ? fs : ".", stdout);
    }
    return true;
}

static const GnuLongOpt realpathLongs[] = {
    {"canonicalize-existing", GNU_NO_ARG, 'e'}, {"canonicalize-missing", GNU_NO_ARG, 'm'},
    {"relative-to", GNU_REQ_ARG, 1},           {"relative-base", GNU_REQ_ARG, 2},
    {"quiet", GNU_NO_ARG, 'q'},                {"strip", GNU_NO_ARG, 's'},
    {"no-symlinks", GNU_NO_ARG, 's'},          {"zero", GNU_NO_ARG, 'z'},
    {"logical", GNU_NO_ARG, 'L'},              {"physical", GNU_NO_ARG, 'P'},
    {"help", GNU_NO_ARG, 3},                   {"version", GNU_NO_ARG, 4},
};

int smallclueRealpathCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "realpath", "eLmPqsz", realpathLongs,
                  sizeof(realpathLongs) / sizeof(realpathLongs[0]));
    int mode = CAN_ALL_BUT_LAST, c, status = 1;
    bool nolinks = false, logical = false, verbose = true;
    char delim = '\n', q[PATH_MAX + 64];
    const char *relTo = NULL, *relBase = NULL;
    char *canTo = NULL, *canBase = NULL;
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'e': mode = CAN_EXISTING; break;
        case 'm': mode = CAN_MISSING; break;
        case 'L': nolinks = true; logical = true; break;
        case 'P': nolinks = false; logical = false; break;
        case 's': nolinks = true; logical = false; break;
        case 'q': verbose = false; break;
        case 'z': delim = '\0'; break;
        case 1: relTo = g.arg; break;
        case 2: relBase = g.arg; break;
        case 3:
            fputs("Usage: realpath [OPTION]... FILE...\n"
                  "Print the resolved absolute file name;\n"
                  "all but the last component must exist\n\n"
                  "  -e, --canonicalize-existing  all components of the path must exist\n"
                  "  -m, --canonicalize-missing   no path components need exist or be a directory\n"
                  "  -L, --logical                resolve '..' components before symlinks\n"
                  "  -P, --physical               resolve symlinks as encountered (default)\n"
                  "  -q, --quiet                  suppress most error messages\n"
                  "      --relative-to=DIR        print the resolved path relative to DIR\n"
                  "      --relative-base=DIR      print absolute paths unless paths below DIR\n"
                  "  -s, --strip, --no-symlinks   don't expand symlinks\n"
                  "  -z, --zero                   end each output line with NUL, not newline\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            status = 0;
            goto done;
        case 4: puts("realpath (SmallCLUE) 9.4"); status = 0; goto done;
        default: status = rlTry("realpath"); goto done;
        }
    }
    if (g.nops == 0) {
        fputs("realpath: missing operand\n", stderr);
        status = rlTry("realpath");
        goto done;
    }
    if (relBase && !relTo) relTo = relBase;
    bool needDir = mode == CAN_EXISTING;
    if (relTo) {
        canTo = rlRealpathCanon(relTo, mode, nolinks, logical);
        struct stat st;
        if (!canTo || (needDir && (stat(canTo, &st) != 0 || !S_ISDIR(st.st_mode)))) {
            if (canTo) errno = ENOTDIR;
            fprintf(stderr, "realpath: %s: %s\n", gnuQuoteMaybe(relTo, q, sizeof(q)), strerror(errno));
            goto done;
        }
    }
    if (relBase == relTo) {
        canBase = canTo ? strdup(canTo) : NULL;
    } else if (relBase) {
        canBase = rlRealpathCanon(relBase, mode, nolinks, logical);
        struct stat st;
        if (!canBase || (needDir && (stat(canBase, &st) != 0 || !S_ISDIR(st.st_mode)))) {
            if (canBase) errno = ENOTDIR;
            fprintf(stderr, "realpath: %s: %s\n", gnuQuoteMaybe(relBase, q, sizeof(q)), strerror(errno));
            goto done;
        }
        /* --relative-to does nothing unless it is below --relative-base */
        if (!rlPrefix(canBase, canTo)) {
            free(canTo);
            free(canBase);
            canTo = canBase = NULL;
        }
    }
    status = 0;
    for (int i = 0; i < g.nops; i++) {
        const char *name = g.ops[i];
        char *can = rlRealpathCanon(name, mode, nolinks, logical);
        if (!can) {
            if (verbose) fprintf(stderr, "realpath: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            status = 1;
            continue;
        }
        if (!canTo || (canBase && !rlPrefix(canBase, can)) || !rlRelpath(can, canTo)) fputs(can, stdout);
        putchar(delim);
        free(can);
    }
done:
    free(canTo);
    free(canBase);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("realpath", errno);
        status = 1;
    }
    return status;
}
