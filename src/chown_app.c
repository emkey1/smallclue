/*
 * chown/chgrp: entirely absent before this. Ownership changes are
 * routine in build/install scripts, even in a single-user guest (e.g.
 * fixing ownership after extracting a tarball as a different UID).
 */

#include "chown_app.h"

#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Parses GNU chown's OWNER[:[GROUP]] spec: "user" (owner only), "user:"
 * (owner only, explicit empty group), "user:group" (both), ":group"
 * (group only). Numeric or named for either side. */
static bool smallclueResolveUidGid(const char *spec, uid_t *uidOut, gid_t *gidOut,
                                    bool *haveUid, bool *haveGid, const char *progName) {
    *haveUid = false;
    *haveGid = false;
    const char *colon = strchr(spec, ':');
    char userPart[256] = {0};
    char groupPart[256] = {0};
    if (colon) {
        size_t ulen = (size_t)(colon - spec);
        if (ulen >= sizeof(userPart)) ulen = sizeof(userPart) - 1;
        memcpy(userPart, spec, ulen);
        userPart[ulen] = '\0';
        strncpy(groupPart, colon + 1, sizeof(groupPart) - 1);
    } else {
        strncpy(userPart, spec, sizeof(userPart) - 1);
    }

    if (userPart[0] != '\0') {
        if (strspn(userPart, "0123456789") == strlen(userPart)) {
            *uidOut = (uid_t)strtoul(userPart, NULL, 10);
            *haveUid = true;
        } else {
            struct passwd *pw = getpwnam(userPart);
            if (!pw) {
                fprintf(stderr, "%s: invalid user: '%s'\n", progName, userPart);
                return false;
            }
            *uidOut = pw->pw_uid;
            *haveUid = true;
        }
    }
    if (colon && groupPart[0] != '\0') {
        if (strspn(groupPart, "0123456789") == strlen(groupPart)) {
            *gidOut = (gid_t)strtoul(groupPart, NULL, 10);
            *haveGid = true;
        } else {
            struct group *gr = getgrnam(groupPart);
            if (!gr) {
                fprintf(stderr, "%s: invalid group: '%s'\n", progName, groupPart);
                return false;
            }
            *gidOut = gr->gr_gid;
            *haveGid = true;
        }
    }
    return true;
}

static int smallclueChownApplyOne(const char *progName, const char *path, bool followSymlink,
                                   bool haveUid, uid_t uid, bool haveGid, gid_t gid) {
    uid_t applyUid = haveUid ? uid : (uid_t)-1;
    gid_t applyGid = haveGid ? gid : (gid_t)-1;
    int rc = followSymlink ? chown(path, applyUid, applyGid) : lchown(path, applyUid, applyGid);
    if (rc != 0) {
        fprintf(stderr, "%s: changing ownership of '%s': %s\n", progName, path, strerror(errno));
        return 1;
    }
    return 0;
}

static int smallclueChownApplyRecursive(const char *progName, const char *path, bool followSymlink,
                                         bool haveUid, uid_t uid, bool haveGid, gid_t gid) {
    int status = smallclueChownApplyOne(progName, path, followSymlink, haveUid, uid, haveGid, gid);
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return status;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "%s: %s: %s\n", progName, path, strerror(errno));
        return 1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= (int)sizeof(child)) {
            fprintf(stderr, "%s: %s/%s: name too long\n", progName, path, entry->d_name);
            status = 1;
            continue;
        }
        if (smallclueChownApplyRecursive(progName, child, followSymlink, haveUid, uid, haveGid, gid) != 0) {
            status = 1;
        }
    }
    closedir(dir);
    return status;
}

int smallclueChownCommand(int argc, char **argv) {
    bool recursive = false;
    bool followSymlink = true; /* default: chown() semantics, follow symlinks */
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-R") == 0 || strcmp(arg, "--recursive") == 0) {
            recursive = true;
            continue;
        }
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--no-dereference") == 0) {
            followSymlink = false;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "chown: unsupported option '%s'\n", arg);
            return 1;
        }
        break;
    }
    if (argi >= argc) {
        fprintf(stderr, "chown: missing operand\n");
        return 1;
    }
    const char *spec = argv[argi++];
    if (argi >= argc) {
        fprintf(stderr, "chown: missing file operand\n");
        return 1;
    }
    uid_t uid = 0;
    gid_t gid = 0;
    bool haveUid = false, haveGid = false;
    if (!smallclueResolveUidGid(spec, &uid, &gid, &haveUid, &haveGid, "chown")) {
        return 1;
    }
    if (!haveUid && !haveGid) {
        fprintf(stderr, "chown: invalid spec '%s'\n", spec);
        return 1;
    }
    int status = 0;
    for (; argi < argc; ++argi) {
        int rc = recursive
            ? smallclueChownApplyRecursive("chown", argv[argi], followSymlink, haveUid, uid, haveGid, gid)
            : smallclueChownApplyOne("chown", argv[argi], followSymlink, haveUid, uid, haveGid, gid);
        if (rc != 0) status = 1;
    }
    return status;
}

int smallclueChgrpCommand(int argc, char **argv) {
    bool recursive = false;
    bool followSymlink = true;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-R") == 0 || strcmp(arg, "--recursive") == 0) {
            recursive = true;
            continue;
        }
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--no-dereference") == 0) {
            followSymlink = false;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "chgrp: unsupported option '%s'\n", arg);
            return 1;
        }
        break;
    }
    if (argi >= argc) {
        fprintf(stderr, "chgrp: missing operand\n");
        return 1;
    }
    const char *groupSpec = argv[argi++];
    if (argi >= argc) {
        fprintf(stderr, "chgrp: missing file operand\n");
        return 1;
    }
    gid_t gid = 0;
    bool haveGid = false;
    if (groupSpec[0] != '\0' && strspn(groupSpec, "0123456789") == strlen(groupSpec)) {
        gid = (gid_t)strtoul(groupSpec, NULL, 10);
        haveGid = true;
    } else {
        struct group *gr = getgrnam(groupSpec);
        if (!gr) {
            fprintf(stderr, "chgrp: invalid group: '%s'\n", groupSpec);
            return 1;
        }
        gid = gr->gr_gid;
        haveGid = true;
    }
    int status = 0;
    for (; argi < argc; ++argi) {
        int rc = recursive
            ? smallclueChownApplyRecursive("chgrp", argv[argi], followSymlink, false, 0, haveGid, gid)
            : smallclueChownApplyOne("chgrp", argv[argi], followSymlink, false, 0, haveGid, gid);
        if (rc != 0) status = 1;
    }
    return status;
}
