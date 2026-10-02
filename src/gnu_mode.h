/*
 * GNU's file mode changes (gnulib modechange.c): the MODE argument of chmod,
 * and of mkdir -m, install -m and find -perm. Octal ("755", "02755") and
 * symbolic ("u+x,g=u,o-rwx", "a=rX", "+t") forms, with GNU's semantics --
 * the umask filters a clause that names no "who", X means execute only for
 * directories and files already executable, and a directory keeps its set-
 * user/group-ID bits unless the mode names them (or is five octal digits).
 * Compiled once, in gnu_util.c.
 */
#ifndef SMALLCLUE_GNU_MODE_H
#define SMALLCLUE_GNU_MODE_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define GNU_MODE_BITS (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

enum { GNU_MODE_ORDINARY, GNU_MODE_X_IF_ANY_X, GNU_MODE_COPY_EXISTING };

typedef struct {
    char op;              /* '=', '+', '-' */
    char flag;
    mode_t affected;      /* 0: no "who" -- the umask decides */
    mode_t value;
    mode_t mentioned;
} GnuModeChange;

typedef struct {
    GnuModeChange *v;
    size_t n;
} GnuMode;

static inline void gnuModeFree(GnuMode *m) {
    free(m->v);
    m->v = NULL;
    m->n = 0;
}

/* false when `s` is not a mode. */
bool gnuModeCompile(const char *s, GnuMode *out);

/* The mode `old` becomes; *changedBits gets the bits the change set or
 * cleared (for mkdir -m's explicit-bits rule), when not NULL. */
mode_t gnuModeAdjust(mode_t old, bool dir, mode_t umaskValue, const GnuMode *m, mode_t *changedBits);

/* ls -l's nine permission characters (no type letter). */
void gnuModeString(mode_t m, char out[10]);

#endif /* SMALLCLUE_GNU_MODE_H */
