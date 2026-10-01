/*
 * GNU's backup naming for cp, mv, ln and install: --backup[=CONTROL] and
 * -b (CONTROL from VERSION_CONTROL, else "existing"), -S SUFFIX (else
 * SIMPLE_BACKUP_SUFFIX, else "~"). Header-only and static.
 */
#ifndef SMALLCLUE_GNU_BACKUP_H
#define SMALLCLUE_GNU_BACKUP_H

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gnu_util.h"

typedef enum { GNU_BACKUP_NONE, GNU_BACKUP_SIMPLE, GNU_BACKUP_NUMBERED, GNU_BACKUP_EXISTING } GnuBackup;

/* NULL or "" means "existing", GNU's default. */
static inline bool gnuBackupParse(const char *s, GnuBackup *out) {
    if (!s || !*s) { *out = GNU_BACKUP_EXISTING; return true; }
    static const struct { const char *name; GnuBackup kind; } names[] = {
        {"none", GNU_BACKUP_NONE}, {"off", GNU_BACKUP_NONE},
        {"simple", GNU_BACKUP_SIMPLE}, {"never", GNU_BACKUP_SIMPLE},
        {"existing", GNU_BACKUP_EXISTING}, {"nil", GNU_BACKUP_EXISTING},
        {"numbered", GNU_BACKUP_NUMBERED}, {"t", GNU_BACKUP_NUMBERED},
    };
    /* Unambiguous abbreviations are accepted, as argmatch does. */
    int found = -1;
    size_t len = strlen(s);
    for (int i = 0; i < 8; i++) {
        if (!strcmp(s, names[i].name)) { *out = names[i].kind; return true; }
        if (!strncmp(s, names[i].name, len)) {
            if (found >= 0 && names[found].kind != names[i].kind) return false;
            found = i;
        }
    }
    if (found < 0) return false;
    *out = names[found].kind;
    return true;
}

/* argmatch's complaint about a bad CONTROL; the caller adds its Try line. */
static inline void gnuBackupComplain(const char *prog, const char *val) {
    char q[512];
    char q2[64];
    fprintf(stderr, "%s: invalid argument %s for %s\nValid arguments are:\n", prog,
            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale("backup type", q2, sizeof(q2)));
    static const char *const rows[][2] = {{"none", "off"}, {"simple", "never"}, {"existing", "nil"}, {"numbered", "t"}};
    for (int i = 0; i < 4; i++) {
        char a[32], b[32];
        fprintf(stderr, "  - %s, %s\n", gnuQuoteLocale(rows[i][0], a, sizeof(a)), gnuQuoteLocale(rows[i][1], b, sizeof(b)));
    }
}

/* The highest N among PATH.~N~ files, or 0. */
static inline long gnuBackupHighest(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    char dir[4096];
    if (!slash) snprintf(dir, sizeof(dir), ".");
    else if (slash == path) snprintf(dir, sizeof(dir), "/");
    else snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
    DIR *d = opendir(dir);
    if (!d) return 0;
    long highest = 0;
    size_t blen = strlen(base);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strncmp(n, base, blen) || strncmp(n + blen, ".~", 2)) continue;
        char *end = NULL;
        long v = strtol(n + blen + 2, &end, 10);
        if (end && end != n + blen + 2 && end[0] == '~' && end[1] == '\0' && v > highest) highest = v;
    }
    closedir(d);
    return highest;
}

/* The name PATH's backup gets; false when it does not fit. */
static inline bool gnuBackupName(GnuBackup kind, const char *suffix, const char *path, char *out, size_t size) {
    long highest = 0;
    if (kind == GNU_BACKUP_NUMBERED || kind == GNU_BACKUP_EXISTING) {
        highest = gnuBackupHighest(path);
        if (kind == GNU_BACKUP_EXISTING) kind = highest > 0 ? GNU_BACKUP_NUMBERED : GNU_BACKUP_SIMPLE;
    }
    int n = kind == GNU_BACKUP_NUMBERED ? snprintf(out, size, "%s.~%ld~", path, highest + 1)
                                        : snprintf(out, size, "%s%s", path, suffix);
    return n >= 0 && (size_t)n < size;
}

static inline const char *gnuBackupSuffix(const char *given) {
    if (given) return given;
    const char *env = getenv("SIMPLE_BACKUP_SUFFIX");
    return env && *env && !strchr(env, '/') ? env : "~";
}

#endif /* SMALLCLUE_GNU_BACKUP_H */
