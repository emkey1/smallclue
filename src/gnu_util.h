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
/* gnulib's locale_quoting_style, as quote() gives it: inside the quotes a
 * backslash is doubled, \a \b \f \n \r \t \v are spelled so, other
 * unprintable bytes (and, outside UTF-8, every byte above 0x7f) become
 * \ooo, and the closing quote is backslashed. */
static inline const char *gnuQuoteLocaleAs(bool utf8, const char *s, char *buf, size_t size) {
    const char *lq = utf8 ? "\xe2\x80\x98" : "'", *rq = utf8 ? "\xe2\x80\x99" : "'";
    size_t rql = strlen(rq), o = 0;
#define GNU_QPUT(str, n) do { size_t n_ = (n); if (o + n_ < size) { memcpy(buf + o, (str), n_); o += n_; } } while (0)
    GNU_QPUT(lq, strlen(lq));
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        static const char named[] = "\a\b\f\n\r\t\v";
        static const char letters[] = "abfnrtv";
        const char *hit = *p ? memchr(named, *p, 7) : NULL;
        if (!strncmp((const char *)p, rq, rql)) {
            GNU_QPUT("\\", 1);
            GNU_QPUT(p, rql);
            p += rql - 1;
        } else if (*p == '\\') {
            GNU_QPUT("\\\\", 2);
        } else if (hit) {
            char e[2] = {'\\', letters[hit - named]};
            GNU_QPUT(e, 2);
        } else if (*p < 0x20 || *p == 0x7f || (*p >= 0x80 && !utf8)) {
            char e[5];
            snprintf(e, sizeof(e), "\\%03o", *p);
            GNU_QPUT(e, 4);
        } else {
            GNU_QPUT(p, 1);
        }
    }
    GNU_QPUT(rq, rql);
#undef GNU_QPUT
    buf[o < size ? o : size - 1] = '\0';
    return buf;
}
/* The style for the locale as the environment has it now; a program that
 * changes its own environment (env -i) passes the style it started with. */
static inline const char *gnuQuoteLocale(const char *s, char *buf, size_t size) {
    return gnuQuoteLocaleAs(gnuUtf8Locale(), s, buf, size);
}

/* GNU's "PROG: write error: ..." -- except for EPIPE while SIGPIPE has its
 * default action, where GNU is already dead from the signal. (A native
 * program gets that signal only once its stdio call returns, so without
 * this the message got out first.) */
#include <errno.h>
#include <signal.h>
static inline void gnuWriteError(const char *prog, int err) {
    if (err == EPIPE) {
        struct sigaction sa;
        if (sigaction(SIGPIPE, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL) return;
    }
    fprintf(stderr, "%s: write error: %s\n", prog, strerror(err));
}

/* GNU's yesno(): one line from stdin, yes when it starts with y or Y. */
static inline bool gnuYes(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return false;
    return line[0] == 'y' || line[0] == 'Y';
}

#endif /* SMALLCLUE_GNU_UTIL_H */
