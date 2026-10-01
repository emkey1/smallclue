/*
 * GNU's file mode changes (gnulib modechange.c): the MODE argument of chmod,
 * and of mkdir -m, install -m and find -perm. Octal ("755", "02755") and
 * symbolic ("u+x,g=u,o-rwx", "a=rX", "+t") forms, with GNU's semantics --
 * the umask filters a clause that names no "who", X means execute only for
 * directories and files already executable, and a directory keeps its set-
 * user/group-ID bits unless the mode names them (or is five octal digits).
 * Header-only and static.
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
static inline bool gnuModeCompile(const char *s, GnuMode *out) {
    out->v = NULL;
    out->n = 0;
    if (*s >= '0' && *s <= '7') {
        mode_t octal = 0;
        const char *p = s;
        for (; *p >= '0' && *p <= '7'; p++) {
            octal = octal * 8 + (mode_t)(*p - '0');
            if (octal > 07777) return false;
        }
        if (*p) return false;
        out->v = (GnuModeChange *)calloc(1, sizeof(GnuModeChange));
        if (!out->v) return false;
        out->v[0].op = '=';
        out->v[0].flag = GNU_MODE_ORDINARY;
        out->v[0].affected = GNU_MODE_BITS;
        out->v[0].value = octal;
        /* Fewer than five digits leave a directory's set-ID bits alone. */
        out->v[0].mentioned = p - s < 5 ? (octal & (S_ISUID | S_ISGID)) | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
                                        : GNU_MODE_BITS;
        out->n = 1;
        return true;
    }
    size_t cap = 0;
    const char *p = s;
    for (;;) {
        mode_t affected = 0;
        for (;; p++) {
            if (*p == 'u') affected |= S_ISUID | S_IRWXU;
            else if (*p == 'g') affected |= S_ISGID | S_IRWXG;
            else if (*p == 'o') affected |= S_ISVTX | S_IRWXO;
            else if (*p == 'a') affected |= GNU_MODE_BITS;
            else break;
        }
        if (*p != '=' && *p != '+' && *p != '-') goto invalid;
        do {
            char op = *p++;
            mode_t value = 0;
            char flag = GNU_MODE_ORDINARY;
            bool octal = false;
            mode_t who = affected;
            if (*p >= '0' && *p <= '7') {
                /* [-+=]OCTAL: every mode bit, and no "who" allowed. */
                if (affected) goto invalid;
                for (; *p >= '0' && *p <= '7'; p++) {
                    value = value * 8 + (mode_t)(*p - '0');
                    if (value > 07777) goto invalid;
                }
                if (*p && *p != ',') goto invalid;
                who = GNU_MODE_BITS;
                octal = true;
            } else if (*p == 'u' || *p == 'g' || *p == 'o') {
                value = *p == 'u' ? S_IRWXU : *p == 'g' ? S_IRWXG : S_IRWXO;
                flag = GNU_MODE_COPY_EXISTING;
                p++;
            } else {
                for (;; p++) {
                    if (*p == 'r') value |= S_IRUSR | S_IRGRP | S_IROTH;
                    else if (*p == 'w') value |= S_IWUSR | S_IWGRP | S_IWOTH;
                    else if (*p == 'x') value |= S_IXUSR | S_IXGRP | S_IXOTH;
                    else if (*p == 'X') flag = GNU_MODE_X_IF_ANY_X;
                    else if (*p == 's') value |= S_ISUID | S_ISGID;
                    else if (*p == 't') value |= S_ISVTX;
                    else break;
                }
            }
            if (out->n == cap) {
                cap = cap ? cap * 2 : 4;
                GnuModeChange *v = (GnuModeChange *)realloc(out->v, cap * sizeof(GnuModeChange));
                if (!v) goto invalid;
                out->v = v;
            }
            GnuModeChange *c = &out->v[out->n++];
            c->op = op;
            c->flag = flag;
            c->affected = who;
            c->value = value;
            c->mentioned = octal ? GNU_MODE_BITS : who ? who & value : value;
        } while (*p == '=' || *p == '+' || *p == '-');
        if (*p != ',') break;
        p++;
    }
    if (*p == '\0') return true;
invalid:
    gnuModeFree(out);
    return false;
}

/* The mode `old` becomes; *changedBits gets the bits the change set or
 * cleared (for mkdir -m's explicit-bits rule), when not NULL. */
static inline mode_t gnuModeAdjust(mode_t old, bool dir, mode_t umaskValue, const GnuMode *m, mode_t *changedBits) {
    mode_t newmode = old & GNU_MODE_BITS;
    mode_t bits = 0;
    for (size_t i = 0; i < m->n; i++) {
        const GnuModeChange *c = &m->v[i];
        mode_t affected = c->affected;
        mode_t omit = (dir ? S_ISUID | S_ISGID : 0) & ~c->mentioned;
        mode_t value = c->value;
        if (c->flag == GNU_MODE_COPY_EXISTING) {
            value &= newmode;
            value |= ((value & (S_IRUSR | S_IRGRP | S_IROTH) ? S_IRUSR | S_IRGRP | S_IROTH : 0) |
                      (value & (S_IWUSR | S_IWGRP | S_IWOTH) ? S_IWUSR | S_IWGRP | S_IWOTH : 0) |
                      (value & (S_IXUSR | S_IXGRP | S_IXOTH) ? S_IXUSR | S_IXGRP | S_IXOTH : 0));
        } else if (c->flag == GNU_MODE_X_IF_ANY_X) {
            if ((newmode & (S_IXUSR | S_IXGRP | S_IXOTH)) || dir) value |= S_IXUSR | S_IXGRP | S_IXOTH;
        }
        value &= (affected ? affected : ~umaskValue) & ~omit;
        if (c->op == '=') {
            mode_t preserved = (affected ? ~affected : 0) | omit;
            bits |= GNU_MODE_BITS & ~preserved;
            newmode = (newmode & preserved) | value;
        } else if (c->op == '+') {
            bits |= value;
            newmode |= value;
        } else {
            bits |= value;
            newmode &= ~value;
        }
    }
    if (changedBits) *changedBits = bits;
    return newmode;
}

/* ls -l's nine permission characters (no type letter). */
static inline void gnuModeString(mode_t m, char out[10]) {
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) out[i] = (m & (0400 >> i)) ? rwx[i] : '-';
    if (m & S_ISUID) out[2] = (m & S_IXUSR) ? 's' : 'S';
    if (m & S_ISGID) out[5] = (m & S_IXGRP) ? 's' : 'S';
    if (m & S_ISVTX) out[8] = (m & S_IXOTH) ? 't' : 'T';
    out[9] = '\0';
}

#endif /* SMALLCLUE_GNU_MODE_H */
