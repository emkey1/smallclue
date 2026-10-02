/*
 * Small helpers shared by the applets that follow GNU coreutils' behaviour:
 * its quoting of file names in messages, and its yes/no prompt answer.
 * Compiled once, in gnu_util.c; none of them keeps state.
 */
#ifndef SMALLCLUE_GNU_UTIL_H
#define SMALLCLUE_GNU_UTIL_H

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* quoteaf (shell-escape-always): 'name', or "name" when it holds a single
 * quote and nothing a double-quoted shell word would expand, else 'a'\''b'. */
const char *gnuQuote(const char *s, char *buf, size_t size);

/* quotef: bare when the name needs no quoting for a shell. */
const char *gnuQuoteMaybe(const char *s, char *buf, size_t size);

/* quote(): GNU's locale quoting -- 'name' in the C locale, and the
 * typographic ‘name’ when the locale's charset is UTF-8. Used for
 * option arguments and some messages (mkdir, chmod, find, rm --interactive). */
#include <stdlib.h>
bool gnuUtf8Locale(void);
/* gnulib's locale_quoting_style, as quote() gives it: inside the quotes a
 * backslash is doubled, \a \b \f \n \r \t \v are spelled so, other
 * unprintable bytes (and, outside UTF-8, every byte above 0x7f) become
 * \ooo, and the closing quote is backslashed. */
const char *gnuQuoteLocaleAs(bool utf8, const char *s, char *buf, size_t size);
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
void gnuWriteError(const char *prog, int err);

/* GNU's yesno(): one line from stdin, yes when it starts with y or Y. */
bool gnuYes(void);

/* A growing byte string, kept NUL-terminated; zero-initialise it. False
 * when memory ran out (the string is then unchanged). */
typedef struct {
    char *s;
    size_t n, cap;
} GnuBuf;
bool gnuBufPut(GnuBuf *b, const char *s, size_t n);
static inline bool gnuBufPutc(GnuBuf *b, char c) { return gnuBufPut(b, &c, 1); }

/* DIR/NAME, with no second slash when DIR ends in one; malloc'd. */
char *gnuPathJoin(const char *dir, const char *name);

/* gnulib's filevercmp, as `sort -V` and `ls -v` use it. */
int gnuFilevercmp(const char *a, size_t al, const char *b, size_t bl);

/* write() until all N bytes are out, through EINTR; false on an error. */
bool gnuWriteAll(int fd, const void *buf, size_t n);

#endif /* SMALLCLUE_GNU_UTIL_H */
