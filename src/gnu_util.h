/*
 * Small helpers shared by the applets that follow GNU coreutils' behaviour:
 * its quoting of file names in messages, and its yes/no prompt answer.
 * Header-only and static, so each applet keeps its own copy and no state.
 */
#ifndef SMALLCLUE_GNU_UTIL_H
#define SMALLCLUE_GNU_UTIL_H

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* quoteaf (shell-escape-always): 'name', or "name" when it holds a single
 * quote and nothing a double-quoted shell word would expand, else 'a'\''b'. */
static inline const char *gnuQuote(const char *s, char *buf, size_t size) {
    bool hasSingle = strchr(s, '\'') != NULL;
    bool doubleOk = hasSingle && !strpbrk(s, "\"$`\\!");
    size_t o = 0;
#define GNU_PUT(c) do { if (o + 1 < size) buf[o++] = (c); } while (0)
    if (doubleOk) {
        GNU_PUT('"');
        for (const char *p = s; *p; p++) GNU_PUT(*p);
        GNU_PUT('"');
    } else {
        GNU_PUT('\'');
        for (const char *p = s; *p; p++) {
            if (*p == '\'') {
                GNU_PUT('\''); GNU_PUT('\\'); GNU_PUT('\''); GNU_PUT('\'');
            } else {
                GNU_PUT(*p);
            }
        }
        GNU_PUT('\'');
    }
#undef GNU_PUT
    buf[o] = '\0';
    return buf;
}

/* quotef: bare when the name needs no quoting for a shell. */
static inline const char *gnuQuoteMaybe(const char *s, char *buf, size_t size) {
    bool plain = *s != '\0';
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || strchr("+-./:=@_%^,", c) || c >= 0x80)) {
            plain = false;
            break;
        }
    }
    if (!plain) return gnuQuote(s, buf, size);
    snprintf(buf, size, "%s", s);
    return buf;
}

/* quote(): GNU's locale quoting -- 'name' in the C locale, and the
 * typographic ‘name’ when the locale's charset is UTF-8. Used for
 * option arguments and some messages (mkdir, chmod, find, rm --interactive). */
#include <stdlib.h>
static inline bool gnuUtf8Locale(void) {
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_CTYPE");
    if (!v || !*v) v = getenv("LANG");
    if (!v) return false;
    return strstr(v, "UTF-8") || strstr(v, "utf8") || strstr(v, "UTF8") || strstr(v, "utf-8");
}
static inline const char *gnuQuoteLocale(const char *s, char *buf, size_t size) {
    if (gnuUtf8Locale())
        snprintf(buf, size, "\xe2\x80\x98%s\xe2\x80\x99", s);
    else
        snprintf(buf, size, "'%s'", s);
    return buf;
}

/* GNU's yesno(): one line from stdin, yes when it starts with y or Y. */
static inline bool gnuYes(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return false;
    return line[0] == 'y' || line[0] == 'Y';
}

#endif /* SMALLCLUE_GNU_UTIL_H */
