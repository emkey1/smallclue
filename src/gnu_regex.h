/*
 * What the applets that take GNU regular expressions share: the compile
 * flags that give the host's regcomp GNU's extensions (\w \s \b \< \> and
 * BRE's \+ \? \| -- REG_ENHANCED on Darwin; glibc has them natively), and
 * glibc's error texts, which GNU tools print and scripts and tests compare.
 * Compiled once, in gnu_util.c.
 */
#ifndef SMALLCLUE_GNU_REGEX_H
#define SMALLCLUE_GNU_REGEX_H

#include <regex.h>

int gnuRegexFlags(int flags);

const char *gnuRegexMessage(int code);

#endif /* SMALLCLUE_GNU_REGEX_H */
