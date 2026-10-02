/* mount and umount for a system whose kernel is Linux.
 *
 * util-linux's interface, the parts scripts use: `mount -t TYPE -o OPTS SRC
 * DIR`, --bind/--rbind/--move, the --make-* propagation flags, -r/-w, -a
 * (everything in /etc/fstab not marked noauto), one-argument mounts looked up
 * in /etc/fstab, and a bare `mount` listing in util-linux's "SRC on DIR type
 * TYPE (OPTS)" form; `umount [-l] [-f] [-R] DIR...`.
 *
 * Two kinds of host compile this. A Linux one calls mount(2) and umount2(2)
 * directly. An embedding whose host is NOT Linux but whose kernel is -- iSH-AOK
 * runs SmallCLUE as host code inside an app that implements Linux -- defines
 * SMALLCLUE_HOST_LINUX_MOUNT and supplies smallclueHostMount and
 * smallclueHostUmount2, which take Linux's arguments and flag values. The flag
 * values below are therefore Linux's own, spelled SC_ so they cannot collide
 * with a host <sys/mount.h> that means something else by MNT_FORCE.
 */

#include "mount_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(linux) || defined(__linux)
#include <sys/mount.h>
#define smallclueSysMount(s, t, ty, f, d) mount((s), (t), (ty), (f), (d))
#define smallclueSysUmount2(t, f) umount2((t), (f))
#define SMALLCLUE_HAVE_LINUX_MOUNT 1
#elif defined(SMALLCLUE_HOST_LINUX_MOUNT)
int smallclueHostMount(const char *source, const char *target, const char *type,
                       unsigned long flags, const void *data);
int smallclueHostUmount2(const char *target, int flags);
#define smallclueSysMount(s, t, ty, f, d) smallclueHostMount((s), (t), (ty), (f), (d))
#define smallclueSysUmount2(t, f) smallclueHostUmount2((t), (f))
#define SMALLCLUE_HAVE_LINUX_MOUNT 1
#endif

#ifdef SMALLCLUE_HAVE_LINUX_MOUNT

#define SC_MS_RDONLY      1UL
#define SC_MS_NOSUID      2UL
#define SC_MS_NODEV       4UL
#define SC_MS_NOEXEC      8UL
#define SC_MS_SYNCHRONOUS 16UL
#define SC_MS_REMOUNT     32UL
#define SC_MS_DIRSYNC     128UL
#define SC_MS_NOATIME     1024UL
#define SC_MS_NODIRATIME  2048UL
#define SC_MS_BIND        4096UL
#define SC_MS_MOVE        8192UL
#define SC_MS_REC         16384UL
#define SC_MS_SILENT      32768UL
#define SC_MS_UNBINDABLE  (1UL << 17)
#define SC_MS_PRIVATE     (1UL << 18)
#define SC_MS_SLAVE       (1UL << 19)
#define SC_MS_SHARED      (1UL << 20)
#define SC_MS_RELATIME    (1UL << 21)
#define SC_MS_STRICTATIME (1UL << 24)
#define SC_MS_LAZYTIME    (1UL << 25)
#define SC_MNT_FORCE      1
#define SC_MNT_DETACH     2

typedef struct {
    const char *name;
    unsigned long set;
    unsigned long clear;
} MountFlagName;

static const MountFlagName mountFlagNames[] = {
    {"ro", SC_MS_RDONLY, 0},          {"rw", 0, SC_MS_RDONLY},
    {"nosuid", SC_MS_NOSUID, 0},      {"suid", 0, SC_MS_NOSUID},
    {"nodev", SC_MS_NODEV, 0},        {"dev", 0, SC_MS_NODEV},
    {"noexec", SC_MS_NOEXEC, 0},      {"exec", 0, SC_MS_NOEXEC},
    {"sync", SC_MS_SYNCHRONOUS, 0},   {"async", 0, SC_MS_SYNCHRONOUS},
    {"dirsync", SC_MS_DIRSYNC, 0},
    {"remount", SC_MS_REMOUNT, 0},
    {"bind", SC_MS_BIND, 0},          {"rbind", SC_MS_BIND | SC_MS_REC, 0},
    {"move", SC_MS_MOVE, 0},
    {"noatime", SC_MS_NOATIME, 0},    {"atime", 0, SC_MS_NOATIME},
    {"nodiratime", SC_MS_NODIRATIME, 0}, {"diratime", 0, SC_MS_NODIRATIME},
    {"relatime", SC_MS_RELATIME, 0},  {"norelatime", 0, SC_MS_RELATIME},
    {"strictatime", SC_MS_STRICTATIME, 0},
    {"lazytime", SC_MS_LAZYTIME, 0},  {"nolazytime", 0, SC_MS_LAZYTIME},
    {"silent", SC_MS_SILENT, 0},      {"loud", 0, SC_MS_SILENT},
    {"private", SC_MS_PRIVATE, 0},    {"rprivate", SC_MS_PRIVATE | SC_MS_REC, 0},
    {"slave", SC_MS_SLAVE, 0},        {"rslave", SC_MS_SLAVE | SC_MS_REC, 0},
    {"shared", SC_MS_SHARED, 0},      {"rshared", SC_MS_SHARED | SC_MS_REC, 0},
    {"unbindable", SC_MS_UNBINDABLE, 0},
    {"runbindable", SC_MS_UNBINDABLE | SC_MS_REC, 0},
};

/* Options that mean something to mount(8) or to fstab, never to the kernel. */
static bool mountOptionIsUserspace(const char *opt) {
    static const char *const names[] = {
        "defaults", "auto", "noauto", "user", "nouser", "users", "owner",
        "group", "nofail", "_netdev", "comment", NULL
    };
    for (int i = 0; names[i]; i++) {
        if (strcmp(opt, names[i]) == 0) {
            return true;
        }
    }
    return strncmp(opt, "x-", 2) == 0 || strncmp(opt, "comment=", 8) == 0;
}

/* Split OPTS into kernel flags and the filesystem's own data string. */
static void mountParseOptions(const char *opts, unsigned long *flags, char **data) {
    if (!opts || !*opts) {
        return;
    }
    char *copy = strdup(opts);
    if (!copy) {
        return;
    }
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        bool known = false;
        for (size_t i = 0; i < sizeof(mountFlagNames) / sizeof(mountFlagNames[0]); i++) {
            if (strcmp(tok, mountFlagNames[i].name) == 0) {
                *flags |= mountFlagNames[i].set;
                *flags &= ~mountFlagNames[i].clear;
                known = true;
                break;
            }
        }
        if (known || mountOptionIsUserspace(tok)) {
            continue;
        }
        size_t have = *data ? strlen(*data) : 0;
        char *grown = realloc(*data, have + strlen(tok) + 2);
        if (!grown) {
            continue;
        }
        if (have) {
            grown[have++] = ',';
        }
        strcpy(grown + have, tok);
        *data = grown;
    }
    free(copy);
}

/* mount(2) has no "auto": util-linux tries each type /proc/filesystems lists
 * without "nodev", which is what this does. */
static int mountAutoProbe(const char *source, const char *target,
                          unsigned long flags, const void *data) {
    FILE *fp = fopen("/proc/filesystems", "r");
    if (!fp) {
        return -1;
    }
    char line[128];
    int lastErrno = ENODEV;
    int rc = -1;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        char *tab = strchr(line, '\t');
        if (!tab || line[0] != '\0' || tab[1] == '\0') {
            continue;   /* "nodev\ttype", or not a line at all */
        }
        if (smallclueSysMount(source, target, tab + 1, flags, data) == 0) {
            rc = 0;
            break;
        }
        lastErrno = errno;
    }
    fclose(fp);
    if (rc != 0) {
        errno = lastErrno;
    }
    return rc;
}

static int mountOne(const char *source, const char *target, const char *type,
                    unsigned long flags, const char *data, bool verbose) {
    int rc;
    bool noType = !type || strcmp(type, "auto") == 0;
    if (flags & (SC_MS_BIND | SC_MS_MOVE | SC_MS_REMOUNT | SC_MS_SHARED | SC_MS_SLAVE |
                 SC_MS_PRIVATE | SC_MS_UNBINDABLE)) {
        /* No filesystem type is involved in any of these. */
        rc = smallclueSysMount(source ? source : "none", target, NULL, flags, data);
    } else if (noType) {
        rc = mountAutoProbe(source, target, flags, data);
    } else {
        rc = smallclueSysMount(source, target, type, flags, data);
    }
    if (rc != 0) {
        fprintf(stderr, "mount: %s: %s\n", target, strerror(errno));
        return 32;   /* util-linux: mount failure */
    }
    if (verbose) {
        printf("mount: %s mounted on %s.\n", source ? source : "none", target);
    }
    return 0;
}

/* A line of /etc/fstab, /proc/mounts or /etc/mtab: the first four fields. */
typedef struct {
    char *source, *target, *type, *opts;
} MountEntry;

static bool mountParseLine(char *line, MountEntry *e) {
    char *save = NULL;
    char *hash = strchr(line, '#');
    if (hash) {
        *hash = '\0';
    }
    e->source = strtok_r(line, " \t\n", &save);
    e->target = strtok_r(NULL, " \t\n", &save);
    e->type = strtok_r(NULL, " \t\n", &save);
    e->opts = strtok_r(NULL, " \t\n", &save);
    return e->source && e->target;
}

static bool mountIsMounted(const char *target) {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) {
        return false;
    }
    char line[1024];
    bool found = false;
    while (!found && fgets(line, sizeof(line), fp)) {
        MountEntry e;
        if (mountParseLine(line, &e) && strcmp(e.target, target) == 0) {
            found = true;
        }
    }
    fclose(fp);
    return found;
}

static bool mountHasOption(const char *opts, const char *name) {
    if (!opts) {
        return false;
    }
    size_t n = strlen(name);
    for (const char *p = opts; p && *p; ) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && strncmp(p, name, n) == 0) {
            return true;
        }
        p = end ? end + 1 : NULL;
    }
    return false;
}

/* `mount -a`, and `mount DIR` / `mount SOURCE` looked up in /etc/fstab. */
static int mountFromFstab(const char *only, unsigned long extraFlags, const char *typeFilter,
                          bool verbose) {
    FILE *fp = fopen("/etc/fstab", "r");
    if (!fp) {
        fprintf(stderr, "mount: /etc/fstab: %s\n", strerror(errno));
        return only ? 1 : 0;
    }
    char line[1024];
    int status = 0;
    bool matched = false;
    while (fgets(line, sizeof(line), fp)) {
        MountEntry e;
        if (!mountParseLine(line, &e)) {
            continue;
        }
        if (only && strcmp(only, e.target) != 0 && strcmp(only, e.source) != 0) {
            continue;
        }
        matched = true;
        if (!only) {
            if (mountHasOption(e.opts, "noauto") || (e.type && strcmp(e.type, "swap") == 0) ||
                strcmp(e.target, "/") == 0 || mountIsMounted(e.target)) {
                continue;
            }
            if (typeFilter && (!e.type || strcmp(typeFilter, e.type) != 0)) {
                continue;
            }
        }
        unsigned long flags = extraFlags;
        char *data = NULL;
        mountParseOptions(e.opts, &flags, &data);
        int rc = mountOne(e.source, e.target, e.type, flags, data, verbose);
        free(data);
        if (rc != 0 && !mountHasOption(e.opts, "nofail")) {
            status = rc;
        }
        if (only) {
            break;
        }
    }
    fclose(fp);
    if (only && !matched) {
        fprintf(stderr, "mount: %s: can't find in /etc/fstab.\n", only);
        return 1;
    }
    return status;
}

static int mountList(const char *typeFilter) {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) {
        fp = fopen("/etc/mtab", "r");
    }
    if (!fp) {
        fprintf(stderr, "mount: cannot read /proc/mounts: %s\n", strerror(errno));
        return 1;
    }
    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        MountEntry e;
        if (!mountParseLine(line, &e)) {
            continue;
        }
        if (typeFilter && (!e.type || strcmp(e.type, typeFilter) != 0)) {
            continue;
        }
        printf("%s on %s type %s (%s)\n", e.source, e.target,
               e.type ? e.type : "unknown", e.opts ? e.opts : "rw");
    }
    fclose(fp);
    return 0;
}

static void mountUsage(FILE *out) {
    fputs("usage: mount [-lv] [-t type]\n"
          "       mount -a [-t type] [-o options]\n"
          "       mount [-rvw] [-t type] [-o options] [source] dir\n"
          "       mount --bind|--rbind|--move olddir newdir\n"
          "       mount --make-[r]{shared,slave,private,unbindable} dir\n",
          out);
}

int smallclueMountLinux(int argc, char **argv) {
    const char *type = NULL;
    char *options = NULL;
    unsigned long flags = 0;
    bool all = false;
    bool verbose = false;
    const char *positional[2] = { NULL, NULL };
    int npos = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *value = NULL;
        if (strcmp(a, "--") == 0) {
            for (i++; i < argc && npos < 2; i++) {
                positional[npos++] = argv[i];
            }
            break;
        }
        if (a[0] != '-' || a[1] == '\0') {
            if (npos >= 2) {
                mountUsage(stderr);
                free(options);
                return 1;
            }
            positional[npos++] = a;
            continue;
        }
        if (strcmp(a, "--bind") == 0 || strcmp(a, "-B") == 0) { flags |= SC_MS_BIND; continue; }
        if (strcmp(a, "--rbind") == 0 || strcmp(a, "-R") == 0) { flags |= SC_MS_BIND | SC_MS_REC; continue; }
        if (strcmp(a, "--move") == 0 || strcmp(a, "-M") == 0) { flags |= SC_MS_MOVE; continue; }
        if (strncmp(a, "--make-", 7) == 0) {
            bool known = false;
            for (size_t k = 0; k < sizeof(mountFlagNames) / sizeof(mountFlagNames[0]); k++) {
                if (strcmp(a + 7, mountFlagNames[k].name) == 0 &&
                    (mountFlagNames[k].set & (SC_MS_SHARED | SC_MS_SLAVE | SC_MS_PRIVATE | SC_MS_UNBINDABLE))) {
                    flags |= mountFlagNames[k].set;
                    known = true;
                }
            }
            if (!known) {
                fprintf(stderr, "mount: unrecognized option '%s'\n", a);
                free(options);
                return 1;
            }
            continue;
        }
        if (strcmp(a, "--read-only") == 0) { flags |= SC_MS_RDONLY; continue; }
        if (strcmp(a, "--rw") == 0 || strcmp(a, "--read-write") == 0) { flags &= ~SC_MS_RDONLY; continue; }
        if (strcmp(a, "--all") == 0) { all = true; continue; }
        if (strcmp(a, "--verbose") == 0) { verbose = true; continue; }
        if (strcmp(a, "--no-mtab") == 0 || strcmp(a, "--show-labels") == 0) { continue; }
        if (strcmp(a, "--help") == 0) { mountUsage(stdout); free(options); return 0; }
        if (strncmp(a, "--types=", 8) == 0) { type = a + 8; continue; }
        if (strncmp(a, "--options=", 10) == 0) { value = a + 10; goto add_options; }
        if (strcmp(a, "--types") == 0 || strcmp(a, "--options") == 0) {
            if (i + 1 >= argc) {
                mountUsage(stderr);
                free(options);
                return 1;
            }
            if (a[2] == 't') {
                type = argv[++i];
                continue;
            }
            value = argv[++i];
            goto add_options;
        }
        if (a[1] == '-') {
            fprintf(stderr, "mount: unrecognized option '%s'\n", a);
            free(options);
            return 1;
        }
        /* Short options, bundled as getopt would take them. */
        for (const char *c = a + 1; *c; c++) {
            switch (*c) {
                case 'a': all = true; break;
                case 'r': flags |= SC_MS_RDONLY; break;
                case 'w': flags &= ~SC_MS_RDONLY; break;
                case 'v': verbose = true; break;
                case 'n': case 'l': case 'f': case 's': break;
                case 'B': flags |= SC_MS_BIND; break;
                case 'R': flags |= SC_MS_BIND | SC_MS_REC; break;
                case 'M': flags |= SC_MS_MOVE; break;
                case 't':
                case 'o': {
                    const char *v = c[1] ? c + 1 : (i + 1 < argc ? argv[++i] : NULL);
                    if (!v) {
                        fprintf(stderr, "mount: option requires an argument -- '%c'\n", *c);
                        free(options);
                        return 1;
                    }
                    if (*c == 't') {
                        type = v;
                    } else {
                        value = v;
                    }
                    goto short_done;   /* the rest of the word was its value */
                }
                default:
                    fprintf(stderr, "mount: invalid option -- '%c'\n", *c);
                    mountUsage(stderr);
                    free(options);
                    return 1;
            }
        }
short_done:
        if (!value) {
            continue;
        }
add_options: {
            size_t have = options ? strlen(options) : 0;
            char *grown = realloc(options, have + strlen(value) + 2);
            if (grown) {
                if (have) {
                    grown[have++] = ',';
                }
                strcpy(grown + have, value);
                options = grown;
            }
        }
    }

    char *data = NULL;
    mountParseOptions(options, &flags, &data);
    free(options);

    int status;
    if (all) {
        status = mountFromFstab(NULL, flags, type, verbose);
    } else if (npos == 0) {
        status = mountList(type);
    } else if (npos == 1 && !(flags & (SC_MS_SHARED | SC_MS_SLAVE | SC_MS_PRIVATE |
                                        SC_MS_UNBINDABLE | SC_MS_REMOUNT))) {
        status = mountFromFstab(positional[0], flags, type, verbose);
    } else if (npos == 1) {
        /* --make-* and remount name only the mount point. */
        status = mountOne(NULL, positional[0], type, flags, data, verbose);
    } else {
        status = mountOne(positional[0], positional[1], type, flags, data, verbose);
    }
    free(data);
    return status;
}

int smallclueUmountLinux(int argc, char **argv) {
    int flags = 0;
    bool verbose = false;
    bool recursive = false;
    int status = 0;
    int targets = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] && a[1] != '-') {
            for (const char *c = a + 1; *c; c++) {
                switch (*c) {
                    case 'l': flags |= SC_MNT_DETACH; break;
                    case 'f': flags |= SC_MNT_FORCE; break;
                    case 'R': recursive = true; break;
                    case 'v': verbose = true; break;
                    case 'n': case 'i': case 'd': case 'r': break;
                    default:
                        fprintf(stderr, "umount: invalid option -- '%c'\n", *c);
                        fputs("usage: umount [-flRv] dir...\n", stderr);
                        return 1;
                }
            }
            continue;
        }
        if (strcmp(a, "--lazy") == 0) { flags |= SC_MNT_DETACH; continue; }
        if (strcmp(a, "--force") == 0) { flags |= SC_MNT_FORCE; continue; }
        if (strcmp(a, "--recursive") == 0) { recursive = true; continue; }
        if (strcmp(a, "--verbose") == 0) { verbose = true; continue; }
        if (strcmp(a, "--no-mtab") == 0) { continue; }
        if (strcmp(a, "--help") == 0) {
            fputs("usage: umount [-flRv] dir...\n", stdout);
            return 0;
        }
        if (a[0] == '-' && a[1] == '-' && a[2]) {
            fprintf(stderr, "umount: unrecognized option '%s'\n", a);
            return 1;
        }
        targets++;
        if (recursive) {
            /* Everything mounted under it first, deepest first: the last
             * entries in /proc/mounts are the most recently mounted. */
            char *list[256];
            int n = 0;
            FILE *fp = fopen("/proc/mounts", "r");
            size_t len = strlen(a);
            while (a[len - 1] == '/' && len > 1) {
                len--;
            }
            if (fp) {
                char line[1024];
                while (n < 256 && fgets(line, sizeof(line), fp)) {
                    MountEntry e;
                    if (mountParseLine(line, &e) && strncmp(e.target, a, len) == 0 &&
                        e.target[len] == '/') {
                        list[n++] = strdup(e.target);
                    }
                }
                fclose(fp);
            }
            for (int k = n - 1; k >= 0; k--) {
                if (list[k] && smallclueSysUmount2(list[k], flags) != 0) {
                    fprintf(stderr, "umount: %s: %s\n", list[k], strerror(errno));
                    status = 32;
                }
                free(list[k]);
            }
        }
        if (smallclueSysUmount2(a, flags) != 0) {
            fprintf(stderr, "umount: %s: %s\n", a, strerror(errno));
            status = 32;
        } else if (verbose) {
            printf("umount: %s unmounted\n", a);
        }
    }
    if (targets == 0) {
        fputs("usage: umount [-flRv] dir...\n", stderr);
        return 1;
    }
    return status;
}

#endif /* SMALLCLUE_HAVE_LINUX_MOUNT */
