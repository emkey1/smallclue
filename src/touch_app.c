/*
 * touch: GNU coreutils 9 compatible. -a -m --time, -c, -h, -d with the
 * full parse-datetime grammar (relative to -r's times when both are given),
 * -t [[CC]YY]MMDDhhmm[.ss] with GNU's range checks and leap second, -r,
 * "-" for standard output, a directory touched in spite of its open
 * failing, and GNU's messages.
 */

#include "touch_app.h"

#include "date_app.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__) && !defined(st_atim)
#define TOUCH_ATIM(st) ((st)->st_atimespec)
#define TOUCH_MTIM(st) ((st)->st_mtimespec)
#else
#define TOUCH_ATIM(st) ((st)->st_atim)
#define TOUCH_MTIM(st) ((st)->st_mtim)
#endif

enum { TOUCH_A = 1, TOUCH_M = 2 };

static int touchTry(void) {
    fputs("Try 'touch --help' for more information.\n", stderr);
    return 1;
}

static bool touchDigits(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i])) return false;
    return true;
}

static int touchTwo(const char *s) {
    return (s[0] - '0') * 10 + (s[1] - '0');
}

/* gnulib posixtime: [[CC]YY]MMDDhhmm[.ss] in local time. */
static bool touchPosixTime(const char *s, time_t *out) {
    const char *dot = strchr(s, '.');
    size_t len = dot ? (size_t)(dot - s) : strlen(s);
    if (!touchDigits(s, len) || (len != 8 && len != 10 && len != 12)) return false;
    if (dot && (strlen(dot + 1) != 2 || !touchDigits(dot + 1, 2))) return false;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    time_t now = time(NULL);
    struct tm cur;
    localtime_r(&now, &cur);
    const char *p = s;
    if (len == 12) {
        tm.tm_year = touchTwo(p) * 100 + touchTwo(p + 2) - 1900;
        p += 4;
    } else if (len == 10) {
        int yy = touchTwo(p);
        tm.tm_year = (yy < 69 ? 2000 : 1900) + yy - 1900;
        p += 2;
    } else {
        tm.tm_year = cur.tm_year;
    }
    tm.tm_mon = touchTwo(p) - 1;
    tm.tm_mday = touchTwo(p + 2);
    tm.tm_hour = touchTwo(p + 4);
    tm.tm_min = touchTwo(p + 6);
    tm.tm_sec = dot ? touchTwo(dot + 1) : 0;
    bool leap = tm.tm_sec == 60;
    if (leap) tm.tm_sec = 59;
    struct tm want = tm;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    /* mktime normalizes; a field it moved was out of range */
    if (tm.tm_year != want.tm_year || tm.tm_mon != want.tm_mon || tm.tm_mday != want.tm_mday ||
        tm.tm_hour != want.tm_hour || tm.tm_min != want.tm_min || tm.tm_sec != want.tm_sec)
        return false;
    *out = t + (leap ? 1 : 0);
    return true;
}

static const GnuLongOpt touchLongs[] = {
    {"time", GNU_REQ_ARG, 1},       {"no-create", GNU_NO_ARG, 'c'}, {"date", GNU_REQ_ARG, 'd'},
    {"reference", GNU_REQ_ARG, 'r'}, {"no-dereference", GNU_NO_ARG, 'h'},
    {"help", GNU_NO_ARG, 2},        {"version", GNU_NO_ARG, 3},
};

int smallclueTouchCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "touch", "acd:fhmr:t:", touchLongs, sizeof(touchLongs) / sizeof(touchLongs[0]));
    int change = 0, status = 1, c;
    bool noCreate = false, noDeref = false, dateSet = false;
    const char *flexDate = NULL, *ref = NULL;
    struct timespec times[2];
    char q[4096];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'a': change |= TOUCH_A; break;
        case 'c': noCreate = true; break;
        case 'd': flexDate = g.arg; break;
        case 'f': break;
        case 'h': noDeref = true; break;
        case 'm': change |= TOUCH_M; break;
        case 'r': ref = g.arg; break;
        case 't': {
            time_t t;
            if (!touchPosixTime(g.arg, &t)) {
                fprintf(stderr, "touch: invalid date format %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto done;
            }
            times[0].tv_sec = t;
            times[0].tv_nsec = 0;
            times[1] = times[0];
            dateSet = true;
            break;
        }
        case 1: {
            static const char *const names[] = {"atime", "access", "use", "mtime", "modify"};
            size_t len = strlen(g.arg);
            int found = -1;
            bool ambiguous = false;
            for (int i = 0; i < 5; i++) {
                if (strncmp(names[i], g.arg, len)) continue;
                if (strlen(names[i]) == len) { found = i; ambiguous = false; break; }
                if (found >= 0 && (found < 3) != (i < 3)) ambiguous = true;
                if (found < 0) found = i;
            }
            if (found < 0 || ambiguous) {
                char q2[64], a1[32], a2[32], a3[32];
                fprintf(stderr, "touch: %s argument %s for %s\nValid arguments are:\n", ambiguous ? "ambiguous" : "invalid",
                        gnuQuoteLocale(g.arg, q, sizeof(q)), gnuQuoteLocale("--time", q2, sizeof(q2)));
                fprintf(stderr, "  - %s, %s, %s\n", gnuQuoteLocale("atime", a1, sizeof(a1)),
                        gnuQuoteLocale("access", a2, sizeof(a2)), gnuQuoteLocale("use", a3, sizeof(a3)));
                fprintf(stderr, "  - %s, %s\n", gnuQuoteLocale("mtime", a1, sizeof(a1)),
                        gnuQuoteLocale("modify", a2, sizeof(a2)));
                goto try;
            }
            change |= found < 3 ? TOUCH_A : TOUCH_M;
            break;
        }
        case 2:
            fputs("Usage: touch [OPTION]... FILE...\n"
                  "Update the access and modification times of each FILE to the current time.\n\n"
                  "A FILE argument that does not exist is created empty, unless -c or -h\n"
                  "is supplied.\n\n"
                  "A FILE argument string of - is handled specially and causes touch to\n"
                  "change the times of the file associated with standard output.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -a                     change only the access time\n"
                  "  -c, --no-create        do not create any files\n"
                  "  -d, --date=STRING      parse STRING and use it instead of current time\n"
                  "  -f                     (ignored)\n"
                  "  -h, --no-dereference   affect each symbolic link instead of any referenced\n"
                  "                         file (useful only on systems that can change the\n"
                  "                         timestamps of a symlink)\n"
                  "  -m                     change only the modification time\n"
                  "  -r, --reference=FILE   use this file's times instead of current time\n"
                  "  -t [[CC]YY]MMDDhhmm[.ss]  use specified time instead of current time,\n"
                  "                         with a date-time format that differs from -d's\n"
                  "      --time=WORD        specify which time to change:\n"
                  "                           access time (-a): 'access', 'atime', 'use';\n"
                  "                           modification time (-m): 'modify', 'mtime'\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            status = 0;
            goto done;
        case 3: puts("touch (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    if (!change) change = TOUCH_A | TOUCH_M;
    if (dateSet && (ref || flexDate)) {
        fputs("touch: cannot specify times from more than one source\n", stderr);
        goto try;
    }
    bool now = false;
    if (ref) {
        struct stat st;
        if ((noDeref ? lstat(ref, &st) : stat(ref, &st)) != 0) {
            fprintf(stderr, "touch: failed to get attributes of %s: %s\n", gnuQuote(ref, q, sizeof(q)),
                    strerror(errno));
            goto done;
        }
        times[0] = TOUCH_ATIM(&st);
        times[1] = TOUCH_MTIM(&st);
        dateSet = true;
        if (flexDate) {
            if (!smallclueParseDatetime(flexDate, times[0], &times[0]) ||
                !smallclueParseDatetime(flexDate, times[1], &times[1])) {
                fprintf(stderr, "touch: invalid date format %s\n", gnuQuoteLocale(flexDate, q, sizeof(q)));
                goto done;
            }
        }
    } else if (flexDate) {
        struct timespec cur;
        clock_gettime(CLOCK_REALTIME, &cur);
        if (!smallclueParseDatetime(flexDate, cur, &times[0])) {
            fprintf(stderr, "touch: invalid date format %s\n", gnuQuoteLocale(flexDate, q, sizeof(q)));
            goto done;
        }
        times[1] = times[0];
        dateSet = true;
        /* "now" itself: let the kernel stamp it, which a writable file not
         * owned by the caller allows */
        now = change == (TOUCH_A | TOUCH_M) && times[0].tv_sec == cur.tv_sec && times[0].tv_nsec == cur.tv_nsec;
    }
    if (!dateSet) now = true;
    if (g.nops == 0) {
        fputs("touch: missing file operand\n", stderr);
        goto try;
    }
    if (change != (TOUCH_A | TOUCH_M)) {
        if (now) {
            times[0].tv_nsec = times[1].tv_nsec = UTIME_NOW;
            now = false;
        }
        times[change == TOUCH_M ? 0 : 1].tv_nsec = UTIME_OMIT;
    }
    status = 0;
    for (int i = 0; i < g.nops; i++) {
        const char *file = g.ops[i];
        int fd = -1, openErr = 0;
        bool isStdout = !strcmp(file, "-");
        if (isStdout) {
            fd = STDOUT_FILENO;
        } else if (!(noCreate || noDeref)) {
            fd = open(file, O_WRONLY | O_CREAT | O_NONBLOCK | O_NOCTTY, 0666);
            if (fd < 0) openErr = errno;
        }
        const struct timespec *t = now ? NULL : times;
        int rc;
        if (fd >= 0) rc = futimens(fd, t);
        else rc = utimensat(AT_FDCWD, file, t, noDeref ? AT_SYMLINK_NOFOLLOW : 0);
        int err = errno;
        if (fd >= 0 && !isStdout) close(fd);
        if (rc == 0) continue;
        if (isStdout && err == EBADF && noCreate) continue;
        if (openErr) {
            fprintf(stderr, "touch: cannot touch %s: %s\n", gnuQuote(file, q, sizeof(q)), strerror(openErr));
        } else {
            if (noCreate && err == ENOENT) continue;
            fprintf(stderr, "touch: setting times of %s: %s\n", gnuQuote(file, q, sizeof(q)), strerror(err));
        }
        status = 1;
    }
    goto done;
try:
    status = touchTry();
done:
    gnuGetoptFree(&g);
    return status;
}
