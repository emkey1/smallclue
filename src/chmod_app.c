/*
 * chmod: change file mode bits, compatible with GNU coreutils 9.
 *
 * The chmod this replaces took -R and a mode only: no -v/-c/-f, no
 * --reference, no X, no copying between classes (g=u), no "s" for the
 * group, and it ignored the umask for clauses without a "who" and cleared
 * a directory's set-group-ID bit under `chmod 755`. Modes now follow
 * gnulib's modechange (gnu_mode.h); the rest follows GNU chmod: -c -f -v
 * with its messages, --reference, -R with -H/-L/-P (symbolic links met while
 * recursing are left alone), --preserve-root (off by default, as in GNU),
 * "-w"-style modes and their umask warning ("new permissions are ...").
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "chmod_app.h"
#include "gnu_mode.h"
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
    GnuMode mode;
    bool haveRef;
    mode_t refMode;
    int verbosity;          /* 0 off, 1 changes, 2 all */
    bool silent, recursive, preserveRoot, diagnoseSurprises;
    char deref;             /* 'P', 'H', 'L' */
    mode_t umask;
    int status;
} Chmod;

static void chmodDescribe(const char *file, mode_t old, mode_t now, int kind) {
    char q[4096], a[10], b[10];
    gnuModeString(old, a);
    gnuModeString(now, b);
    switch (kind) {
    case 0: printf("mode of %s changed from %04lo (%s) to %04lo (%s)\n", gnuQuote(file, q, sizeof(q)),
                   (unsigned long)(old & 07777), a, (unsigned long)(now & 07777), b); break;
    case 1: printf("failed to change mode of %s from %04lo (%s) to %04lo (%s)\n", gnuQuote(file, q, sizeof(q)),
                   (unsigned long)(old & 07777), a, (unsigned long)(now & 07777), b); break;
    case 2: printf("mode of %s retained as %04lo (%s)\n", gnuQuote(file, q, sizeof(q)), (unsigned long)(now & 07777), b); break;
    default: printf("neither symbolic link %s nor referent has been changed\n", gnuQuote(file, q, sizeof(q))); break;
    }
}

static void chmodOne(Chmod *c, const char *path, bool top);

static void chmodTree(Chmod *c, const char *path) {
    char q[4096];
    DIR *d = opendir(path);
    if (!d) {
        if (!c->silent) fprintf(stderr, "chmod: cannot read directory %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(errno));
        c->status = 1;
        return;
    }
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
    size_t pl = strlen(path);
    for (size_t i = 0; i < n; i++) {
        size_t len = pl + strlen(names[i]) + 2;
        char *child = (char *)malloc(len);
        if (child) {
            snprintf(child, len, "%s%s%s", path, pl && path[pl - 1] == '/' ? "" : "/", names[i]);
            chmodOne(c, child, false);
            free(child);
        }
        free(names[i]);
    }
    free(names);
}

static void chmodOne(Chmod *c, const char *path, bool top) {
    char q[4096];
    struct stat st;
    bool follow = c->deref == 'L' || top;
    if (lstat(path, &st) != 0) {
        if (!c->silent) fprintf(stderr, "chmod: cannot access %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(errno));
        if (c->verbosity == 2) printf("%s could not be accessed\n", gnuQuote(path, q, sizeof(q)));
        c->status = 1;
        return;
    }
    if (S_ISLNK(st.st_mode)) {
        if (!follow || (!top && c->deref == 'H')) {
            /* A link met while recursing: GNU changes neither it nor its target. */
            if (c->verbosity == 2) chmodDescribe(path, 0, 0, 3);
            return;
        }
        if (stat(path, &st) != 0) {
            if (!c->silent) fprintf(stderr, "chmod: cannot operate on dangling symlink %s\n", gnuQuote(path, q, sizeof(q)));
            if (c->verbosity == 2) printf("%s could not be accessed\n", gnuQuote(path, q, sizeof(q)));
            c->status = 1;
            return;
        }
    }
    if (c->recursive && c->preserveRoot && S_ISDIR(st.st_mode)) {
        struct stat root;
        if (stat("/", &root) == 0 && root.st_dev == st.st_dev && root.st_ino == st.st_ino) {
            if (!strcmp(path, "/"))
                fprintf(stderr, "chmod: it is dangerous to operate recursively on '/'\n");
            else
                fprintf(stderr, "chmod: it is dangerous to operate recursively on %s (same as '/')\n", gnuQuote(path, q, sizeof(q)));
            fputs("chmod: use --no-preserve-root to override this failsafe\n", stderr);
            c->status = 1;
            return;
        }
    }
    mode_t old = st.st_mode;
    bool dir = S_ISDIR(old);
    mode_t now = c->haveRef ? c->refMode : gnuModeAdjust(old, dir, c->umask, &c->mode, NULL);
    bool ok = chmod(path, now) == 0;
    if (!ok) {
        int err = errno;
        if (!c->silent) fprintf(stderr, "chmod: changing permissions of %s: %s\n", gnuQuote(path, q, sizeof(q)), strerror(err));
        c->status = 1;
    }
    if (c->verbosity) {
        bool changed = ok && (old & 07777) != (now & 07777);
        if (changed || c->verbosity == 2) chmodDescribe(path, old, now, !ok ? 1 : changed ? 0 : 2);
    }
    if (ok && c->diagnoseSurprises && !c->haveRef) {
        mode_t naive = gnuModeAdjust(old, dir, 0, &c->mode, NULL);
        if (now & ~naive) {
            char a[10], b[10];
            gnuModeString(now, a);
            gnuModeString(naive, b);
            fprintf(stderr, "chmod: %s: new permissions are %s, not %s\n", gnuQuoteMaybe(path, q, sizeof(q)), a, b);
            c->status = 1;
        }
    }
    if (c->recursive && dir) chmodTree(c, path);
}

static int chmodTry(void) {
    fputs("Try 'chmod --help' for more information.\n", stderr);
    return 1;
}

static void chmodUsage(void) {
    fputs("Usage: chmod [OPTION]... MODE[,MODE]... FILE...\n"
          "  or:  chmod [OPTION]... OCTAL-MODE FILE...\n"
          "  or:  chmod [OPTION]... --reference=RFILE FILE...\n"
          "Change the mode of each FILE to MODE.\n"
          "With --reference, change the mode of each FILE to that of RFILE.\n\n"
          "  -c, --changes          like verbose but report only when a change is made\n"
          "  -f, --silent, --quiet  suppress most error messages\n"
          "  -v, --verbose          output a diagnostic for every file processed\n"
          "      --no-preserve-root  do not treat '/' specially (the default)\n"
          "      --preserve-root    fail to operate recursively on '/'\n"
          "      --reference=RFILE  use RFILE's mode instead of specifying MODE values.\n"
          "  -R, --recursive        change files and directories recursively\n"
          "  -H, -L, -P             with -R: follow command-line links, all links, none\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n\n"
          "Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.\n",
          stdout);
}

int smallclueChmodCommand(int argc, char **argv) {
    Chmod c;
    memset(&c, 0, sizeof(c));
    c.deref = 'P';
    mode_t um = umask(0);
    umask(um);
    c.umask = um;
    const char *modeArg = NULL, *refFile = NULL;
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nfiles = 0, status = 1;
    if (!files) return 1;
    static const struct { const char *name; int c; int arg; } longs[] = {
        {"changes", 'c', 0}, {"silent", 'f', 0}, {"quiet", 'f', 0}, {"verbose", 'v', 0},
        {"no-preserve-root", 1, 0}, {"preserve-root", 2, 0}, {"reference", 3, 1}, {"recursive", 'R', 0},
        {"help", 4, 0}, {"version", 5, 0},
    };
    bool endOfOptions = false;
    char q[4096];
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            files[nfiles++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            int m = -1, matches = 0;
            for (int k = 0; k < (int)(sizeof(longs) / sizeof(longs[0])); k++) {
                if (strncmp(longs[k].name, opt, len)) continue;
                if (strlen(longs[k].name) == len) { m = k; matches = 1; break; }
                if (m >= 0 && longs[m].c == longs[k].c) continue;
                m = k;
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "chmod: option '%s' is ambiguous\n" : "chmod: unrecognized option '%s'\n", arg);
                status = chmodTry();
                goto done;
            }
            const char *val = NULL;
            if (longs[m].arg) {
                if (eq) val = eq + 1;
                else if (i + 1 < argc) val = argv[++i];
                else {
                    fprintf(stderr, "chmod: option '--%s' requires an argument\n", longs[m].name);
                    status = chmodTry();
                    goto done;
                }
            } else if (eq) {
                fprintf(stderr, "chmod: option '--%s' doesn't allow an argument\n", longs[m].name);
                status = chmodTry();
                goto done;
            }
            switch (longs[m].c) {
            case 'c': c.verbosity = 1; break;
            case 'f': c.silent = true; break;
            case 'v': c.verbosity = 2; break;
            case 'R': c.recursive = true; break;
            case 1: c.preserveRoot = false; break;
            case 2: c.preserveRoot = true; break;
            case 3: refFile = val; break;
            case 4: chmodUsage(); status = 0; goto done;
            default: puts("chmod (SmallCLUE) 9.4"); status = 0; goto done;
            }
            continue;
        }
        /* "-w", "-x", "-755": a mode, as GNU reads them, the first time. */
        if (strchr("rwxXstugoa,+-=01234567", arg[1]) && !modeArg) {
            modeArg = arg;
            c.diagnoseSurprises = true;
            continue;
        }
        for (const char *p = arg + 1; *p; p++) {
            switch (*p) {
            case 'c': c.verbosity = 1; break;
            case 'f': c.silent = true; break;
            case 'v': c.verbosity = 2; break;
            case 'R': c.recursive = true; break;
            case 'H': case 'L': case 'P': c.deref = *p; break;
            default:
                fprintf(stderr, "chmod: invalid option -- '%c'\n", *p);
                status = chmodTry();
                goto done;
            }
        }
    }
    int first = 0;
    if (!refFile && !modeArg) {
        if (nfiles == 0) {
            fputs("chmod: missing operand\n", stderr);
            status = chmodTry();
            goto done;
        }
        modeArg = files[0];
        first = 1;
    }
    if (first >= nfiles) {
        if (modeArg && !refFile && first == 1)
            fprintf(stderr, "chmod: missing operand after %s\n", gnuQuoteLocale(modeArg, q, sizeof(q)));
        else
            fputs("chmod: missing operand\n", stderr);
        status = chmodTry();
        goto done;
    }
    if (refFile) {
        struct stat st;
        if (stat(refFile, &st) != 0) {
            fprintf(stderr, "chmod: failed to get attributes of %s: %s\n", gnuQuote(refFile, q, sizeof(q)), strerror(errno));
            goto done;
        }
        c.haveRef = true;
        c.refMode = st.st_mode & 07777;
    } else if (!gnuModeCompile(modeArg, &c.mode)) {
        fprintf(stderr, "chmod: invalid mode: %s\n", gnuQuoteLocale(modeArg, q, sizeof(q)));
        status = chmodTry();
        goto done;
    }
    for (int k = first; k < nfiles; k++) chmodOne(&c, files[k], true);
    status = c.status;

done:
    gnuModeFree(&c.mode);
    free(files);
    if (fflush(stdout) != 0) status = 1;
    return status;
}
