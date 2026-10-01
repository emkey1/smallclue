/*
 * What the applets that take GNU regular expressions share: the compile
 * flags that give the host's regcomp GNU's extensions (\w \s \b \< \> and
 * BRE's \+ \? \| -- REG_ENHANCED on Darwin; glibc has them natively), and
 * glibc's error texts, which GNU tools print and scripts and tests compare.
 * Header-only and static.
 */
#ifndef SMALLCLUE_GNU_REGEX_H
#define SMALLCLUE_GNU_REGEX_H

#include <regex.h>

static inline int gnuRegexFlags(int flags) {
#ifdef REG_ENHANCED
    flags |= REG_ENHANCED;
#endif
    return flags;
}

static inline const char *gnuRegexMessage(int code) {
    switch (code) {
    case REG_EPAREN: return "Unmatched ( or \\(";
    case REG_EBRACK: return "Unmatched [, [^, [:, [., or [=";
    case REG_EBRACE: return "Unmatched \\{";
    case REG_BADBR: return "Invalid content of \\{\\}";
    case REG_BADRPT: return "Invalid preceding regular expression";
    case REG_EESCAPE: return "Trailing backslash";
    case REG_ERANGE: return "Invalid range end";
    case REG_ECTYPE: return "Invalid character class name";
    case REG_ESUBREG: return "Invalid back reference";
    case REG_ECOLLATE: return "Invalid collation character";
    case REG_ESPACE: return "Memory exhausted";
    default: return "Invalid regular expression";
    }
}

#endif /* SMALLCLUE_GNU_REGEX_H */
