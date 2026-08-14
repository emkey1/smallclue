/*
 * chroot: entirely absent before this. Useful for running a command
 * (or a shell) with its filesystem root changed, e.g. testing a
 * freshly extracted rootfs or sandboxing a build step.
 */

#include "chroot_app.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool smallclueChrootResolveUser(const char *spec, uid_t *uidOut, gid_t *gidOut,
                                        bool *haveGid) {
    *haveGid = false;
    if (strspn(spec, "0123456789") == strlen(spec) && spec[0] != '\0') {
        *uidOut = (uid_t)strtoul(spec, NULL, 10);
        return true;
    }
    struct passwd *pw = getpwnam(spec);
    if (!pw) {
        fprintf(stderr, "chroot: invalid user: '%s'\n", spec);
        return false;
    }
    *uidOut = pw->pw_uid;
    *gidOut = pw->pw_gid;
    *haveGid = true;
    return true;
}

static bool smallclueChrootResolveGroup(const char *spec, gid_t *gidOut) {
    if (strspn(spec, "0123456789") == strlen(spec) && spec[0] != '\0') {
        *gidOut = (gid_t)strtoul(spec, NULL, 10);
        return true;
    }
    struct group *gr = getgrnam(spec);
    if (!gr) {
        fprintf(stderr, "chroot: invalid group: '%s'\n", spec);
        return false;
    }
    *gidOut = gr->gr_gid;
    return true;
}

int smallclueChrootCommand(int argc, char **argv) {
    int argi = 1;
    const char *userSpec = NULL;
    const char *groupSpec = NULL;

    while (argi < argc) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-u") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "chroot: option '-u' requires an argument\n");
                return 1;
            }
            userSpec = argv[++argi];
            argi++;
            continue;
        }
        if (strcmp(arg, "-g") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "chroot: option '-g' requires an argument\n");
                return 1;
            }
            groupSpec = argv[++argi];
            argi++;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "chroot: unsupported option '%s'\n", arg);
            return 1;
        }
        break;
    }

    if (argi >= argc) {
        fprintf(stderr, "usage: chroot [-u USER] [-g GROUP] NEWROOT [COMMAND [ARG]...]\n");
        return 1;
    }

    const char *newRoot = argv[argi++];

    uid_t uid = 0;
    gid_t gid = 0;
    bool haveUid = false;
    bool haveGid = false;
    if (userSpec) {
        gid_t pwGid = 0;
        bool pwHaveGid = false;
        if (!smallclueChrootResolveUser(userSpec, &uid, &pwGid, &pwHaveGid)) {
            return 1;
        }
        haveUid = true;
        if (pwHaveGid) {
            gid = pwGid;
            haveGid = true;
        }
    }
    if (groupSpec) {
        if (!smallclueChrootResolveGroup(groupSpec, &gid)) {
            return 1;
        }
        haveGid = true;
    }

    if (chroot(newRoot) != 0) {
        fprintf(stderr, "chroot: cannot chroot to '%s': %s\n", newRoot, strerror(errno));
        return 1;
    }
    if (chdir("/") != 0) {
        fprintf(stderr, "chroot: cannot chdir to '/': %s\n", strerror(errno));
        return 1;
    }

    if (haveGid && setgid(gid) != 0) {
        fprintf(stderr, "chroot: cannot set group id: %s\n", strerror(errno));
        return 1;
    }
    if (haveUid && setuid(uid) != 0) {
        fprintf(stderr, "chroot: cannot set user id: %s\n", strerror(errno));
        return 1;
    }

    char *fallbackArgs[] = {NULL, NULL};
    char **execArgv;
    if (argi < argc) {
        execArgv = &argv[argi];
    } else {
        const char *shell = getenv("SHELL");
        if (!shell || shell[0] == '\0') {
            shell = "/bin/sh";
        }
        fallbackArgs[0] = (char *)shell;
        execArgv = fallbackArgs;
    }

    execvp(execArgv[0], execArgv);
    fprintf(stderr, "chroot: cannot execute '%s': %s\n", execArgv[0], strerror(errno));
    return 127;
}
