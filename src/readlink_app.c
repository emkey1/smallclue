/*
 * readlink/realpath applet: path canonicalization is a ubiquitous shell-
 * script idiom (`cd "$(dirname "$(readlink -f "$0")")"` and friends) that
 * had no equivalent applet at all.
 */

#include "readlink_app.h"

#include <errno.h>
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

/* Canonicalizes `path`, resolving symlinks and .././ components. libc's
 * realpath(3) already does this correctly for a fully-existing path; when
 * `allowMissing` is set and some suffix of the path doesn't exist, we
 * canonicalize the longest existing prefix via realpath(3) and manually
 * append the (nonexistent) remainder, matching GNU readlink -f/-m's more
 * lenient behavior instead of libc realpath()'s hard "all components must
 * exist" requirement. */
static bool smallclueCanonicalize(const char *path, bool allowMissing, char *out, size_t outLen) {
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL) {
        snprintf(out, outLen, "%s", resolved);
        return true;
    }
    if (!allowMissing || errno != ENOENT) {
        return false;
    }

    /* Walk backwards, chopping off trailing components, until realpath()
     * succeeds on the remaining prefix. */
    char working[PATH_MAX];
    snprintf(working, sizeof(working), "%s", path);
    char suffix[PATH_MAX];
    suffix[0] = '\0';

    for (;;) {
        char *slash = strrchr(working, '/');
        char component[PATH_MAX];
        if (!slash) {
            snprintf(component, sizeof(component), "%s", working);
            working[0] = '.';
            working[1] = '\0';
        } else if (slash == working) {
            snprintf(component, sizeof(component), "%s", slash + 1);
            working[1] = '\0';
        } else {
            snprintf(component, sizeof(component), "%s", slash + 1);
            *slash = '\0';
        }
        if (component[0] != '\0') {
            char newSuffix[PATH_MAX];
            if (suffix[0] != '\0') {
                snprintf(newSuffix, sizeof(newSuffix), "%s/%s", component, suffix);
            } else {
                snprintf(newSuffix, sizeof(newSuffix), "%s", component);
            }
            snprintf(suffix, sizeof(suffix), "%s", newSuffix);
        }
        if (realpath(working, resolved) != NULL) {
            if (suffix[0] != '\0') {
                snprintf(out, outLen, "%s/%s", resolved, suffix);
            } else {
                snprintf(out, outLen, "%s", resolved);
            }
            return true;
        }
        if (errno != ENOENT || (strcmp(working, "/") == 0) || (strcmp(working, ".") == 0)) {
            return false;
        }
    }
}

int smallclueReadlinkCommand(int argc, char **argv) {
    bool canonicalize = false;
    bool requireExisting = false;
    bool allowMissing = false;
    bool noNewline = false;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (arg[0] != '-' || strcmp(arg, "-") == 0) {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        for (const char *p = arg + 1; *p; ++p) {
            switch (*p) {
                case 'f': canonicalize = true; break;
                case 'e': canonicalize = true; requireExisting = true; break;
                case 'm': canonicalize = true; allowMissing = true; break;
                case 'n': noNewline = true; break;
                default:
                    fprintf(stderr, "readlink: unsupported option '%c'\n", *p);
                    return 1;
            }
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "readlink: missing operand\n");
        return 1;
    }

    int status = 0;
    for (int i = argi; i < argc; ++i) {
        const char *path = argv[i];
        char resolved[PATH_MAX];
        if (canonicalize) {
            bool lenient = allowMissing || !requireExisting;
            if (!smallclueCanonicalize(path, lenient, resolved, sizeof(resolved))) {
                fprintf(stderr, "readlink: %s: %s\n", path, strerror(errno));
                status = 1;
                continue;
            }
            fputs(resolved, stdout);
        } else {
            ssize_t n = readlink(path, resolved, sizeof(resolved) - 1);
            if (n < 0) {
                fprintf(stderr, "readlink: %s: %s\n", path, strerror(errno));
                status = 1;
                continue;
            }
            resolved[n] = '\0';
            fputs(resolved, stdout);
        }
        if (!noNewline) {
            putchar('\n');
        }
    }
    return status;
}

int smallclueRealpathCommand(int argc, char **argv) {
    bool allowMissing = true; /* GNU realpath's default: missing final component OK */

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (arg[0] != '-' || strcmp(arg, "-") == 0) {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-m") == 0 || strcmp(arg, "--canonicalize-missing") == 0) {
            allowMissing = true;
        } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--canonicalize-existing") == 0) {
            allowMissing = false;
        } else {
            fprintf(stderr, "realpath: unsupported option '%s'\n", arg);
            return 1;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "realpath: missing operand\n");
        return 1;
    }

    int status = 0;
    for (int i = argi; i < argc; ++i) {
        const char *path = argv[i];
        char resolved[PATH_MAX];
        /* GNU realpath defaults to allowing a missing final component;
         * -e demands every component (including the last) exist. */
        if (!smallclueCanonicalize(path, allowMissing, resolved, sizeof(resolved))) {
            fprintf(stderr, "realpath: %s: %s\n", path, strerror(errno));
            status = 1;
            continue;
        }
        printf("%s\n", resolved);
    }
    return status;
}
