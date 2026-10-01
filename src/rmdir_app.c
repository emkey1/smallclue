/*
 * rmdir: GNU coreutils 9 compatible. -p removes each parent in turn (GNU's
 * remove_parents: trailing and doubled slashes skipped), -v reports on
 * stdout, --ignore-fail-on-non-empty skips a directory that still holds
 * something (ENOTEMPTY/EEXIST, or EACCES/EPERM/EROFS/EBUSY with entries),
 * and GNU's messages, the symlink-with-a-trailing-slash one included.
 */

#include "rmdir_app.h"

#include "gnu_getopt.h"
#include "gnu_util.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    bool parents, verbose, ignoreNonEmpty;
    const char *prog;   /* argv[0], as GNU's prog_fprintf names itself */
} Rmdir;

/* is_empty_dir: true for an empty directory; errno 0 when it has entries. */
static bool rmdirEmpty(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return false;
    struct dirent *e;
    errno = 0;
    bool empty = true;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            empty = false;
            break;
        }
    }
    int err = errno;
    closedir(d);
    errno = empty ? err : 0;
    return empty;
}

static bool rmdirIgnorable(const Rmdir *r, int err, const char *dir) {
    if (!r->ignoreNonEmpty) return false;
    if (err == ENOTEMPTY || err == EEXIST) return true;
    if (err == EACCES || err == EPERM || err == EROFS || err == EBUSY) return !rmdirEmpty(dir) && errno == 0;
    return false;
}

static void rmdirVerbose(const Rmdir *r, const char *dir) {
    char q[4096];
    if (r->verbose) printf("%s: removing directory, %s\n", r->prog, gnuQuote(dir, q, sizeof(q)));
}

static bool rmdirParents(const Rmdir *r, char *dir) {
    char q[4096];
    size_t n = strlen(dir);
    while (n > 1 && dir[n - 1] == '/') dir[--n] = '\0';
    for (;;) {
        char *slash = strrchr(dir, '/');
        if (!slash) return true;
        while (slash > dir && *slash == '/') --slash;
        slash[1] = '\0';
        rmdirVerbose(r, dir);
        if (rmdir(dir) == 0) continue;
        int err = errno;
        if (rmdirIgnorable(r, err, dir)) return true;
        fprintf(stderr, err != ENOTDIR ? "rmdir: failed to remove directory %s: %s\n"
                                       : "rmdir: failed to remove %s: %s\n",
                gnuQuote(dir, q, sizeof(q)), strerror(err));
        return false;
    }
}

static const GnuLongOpt rmdirLongs[] = {
    {"ignore-fail-on-non-empty", GNU_NO_ARG, 1}, {"parents", GNU_NO_ARG, 'p'},
    {"verbose", GNU_NO_ARG, 'v'},                 {"help", GNU_NO_ARG, 2},
    {"version", GNU_NO_ARG, 3},
};

int smallclueRmdirCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "rmdir", "pv", rmdirLongs, sizeof(rmdirLongs) / sizeof(rmdirLongs[0]));
    Rmdir r = {false, false, false, argc > 0 && argv[0] ? argv[0] : "rmdir"};
    int c, status = 0;
    char q[4096];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'p': r.parents = true; break;
        case 'v': r.verbose = true; break;
        case 1: r.ignoreNonEmpty = true; break;
        case 2:
            fputs("Usage: rmdir [OPTION]... DIRECTORY...\n"
                  "Remove the DIRECTORY(ies), if they are empty.\n\n"
                  "      --ignore-fail-on-non-empty\n"
                  "                    ignore each failure to remove a non-empty directory\n"
                  "  -p, --parents     remove DIRECTORY and its ancestors;\n"
                  "                    e.g., 'rmdir -p a/b' is similar to 'rmdir a/b a'\n"
                  "  -v, --verbose     output a diagnostic for every directory processed\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            goto done;
        case 3: puts("rmdir (SmallCLUE) 9.4"); goto done;
        default: goto try;
        }
    }
    if (g.nops == 0) {
        fputs("rmdir: missing operand\n", stderr);
        goto try;
    }
    for (int i = 0; i < g.nops; i++) {
        const char *dir = g.ops[i];
        rmdirVerbose(&r, dir);
        if (rmdir(dir) != 0) {
            int err = errno;
            if (rmdirIgnorable(&r, err, dir)) continue;
            bool custom = false;
            size_t n = strlen(dir);
            if (err == ENOTDIR && n && dir[n - 1] == '/') {
                /* "dir-link/": the link, not its target, was asked for */
                char *bare = strdup(dir);
                while (n > 1 && bare[n - 1] == '/') bare[--n] = '\0';
                struct stat st;
                if (lstat(bare, &st) == 0 && S_ISLNK(st.st_mode) && stat(bare, &st) == 0 && S_ISDIR(st.st_mode)) {
                    fprintf(stderr, "rmdir: failed to remove %s: Symbolic link not followed\n",
                            gnuQuote(dir, q, sizeof(q)));
                    custom = true;
                }
                free(bare);
            }
            if (!custom) fprintf(stderr, "rmdir: failed to remove %s: %s\n", gnuQuote(dir, q, sizeof(q)), strerror(err));
            status = 1;
        } else if (r.parents) {
            char *copy = strdup(dir);
            if (!rmdirParents(&r, copy)) status = 1;
            free(copy);
        }
    }
    goto done;
try:
    fputs("Try 'rmdir --help' for more information.\n", stderr);
    status = 1;
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("rmdir", errno);
        status = 1;
    }
    return status;
}
