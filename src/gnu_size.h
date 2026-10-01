/*
 * GNU coreutils' count suffixes (xstrtoumax with "bkKmMGTPEZYRQ0", as head,
 * tail and split use): b 512, k/K 1024, m/M 1024^2, G, T, ... Q; and a
 * second suffix "B" or "D" for powers of 1000 (kB, MB), "iB" for 1024
 * (KiB). Header-only and static.
 */
#ifndef SMALLCLUE_GNU_SIZE_H
#define SMALLCLUE_GNU_SIZE_H

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* 0 on success; 1 when not a number; 2 when it does not fit. A leading '+'
 * is allowed; the caller strips any sign it gives a meaning to. */
static inline int gnuParseSize(const char *s, uintmax_t *out) {
    if (*s == '+') s++;
    if (!isdigit((unsigned char)*s)) return 1;
    char *end;
    errno = 0;
    uintmax_t v = strtoumax(s, &end, 10);
    bool overflow = errno == ERANGE;
    if (*end == '\0') {
        if (overflow) return 2;
        *out = v;
        return 0;
    }
    static const char powers[] = "KMGTPEZYRQ";
    uintmax_t mult = 1;
    char u = *end;
    const char *rest = end + 1;
    if (u == 'b') {
        mult = 512;
    } else {
        char up = u == 'k' ? 'K' : u == 'm' ? 'M' : u;
        const char *pos = up ? strchr(powers, up) : NULL;
        if (!pos) return 1;
        unsigned base = 1024;
        if (!strcmp(rest, "B") || !strcmp(rest, "D")) {
            base = 1000;
            rest++;
        } else if (!strcmp(rest, "iB")) {
            rest += 2;
        }
        for (int i = 0; i <= (int)(pos - powers); i++) {
            if (mult > UINTMAX_MAX / base) return 2;
            mult *= base;
        }
    }
    if (*rest != '\0') return 1;
    if (overflow || (v != 0 && mult > UINTMAX_MAX / v)) return 2;
    *out = v * mult;
    return 0;
}

#endif /* SMALLCLUE_GNU_SIZE_H */
