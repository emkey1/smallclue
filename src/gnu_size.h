/*
 * GNU coreutils' count suffixes (xstrtoumax with "bkKmMGTPEZYRQ0", as head,
 * tail and split use): b 512, k/K 1024, m/M 1024^2, G, T, ... Q; and a
 * second suffix "B" or "D" for powers of 1000 (kB, MB), "iB" for 1024
 * (KiB). Compiled once, in gnu_util.c.
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
int gnuParseSize(const char *s, uintmax_t *out);

#endif /* SMALLCLUE_GNU_SIZE_H */
