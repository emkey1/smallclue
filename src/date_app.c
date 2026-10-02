/*
 * date: print or set the system date and time, compatible with GNU
 * coreutils 9 (C and C.UTF-8 locales).
 *
 * The date this replaces read options only before the format, took only
 * YYYY-MM-DD[ HH:MM[:SS]] for -d (no @SECONDS, no relative dates, no time
 * zones), had no -r, -R, -I or --rfc-3339, and formatted with the host's
 * strftime -- which on Darwin knows neither %N nor %:z nor GNU's padding
 * flags (%-d, %_H, %^a, %10Y).
 *
 * This parses -d strings by GNU's grammar (parse-datetime.y): @SECONDS, ISO
 * 8601 dates, times and offsets, slash dates, month and day names, numbers
 * by GNU's digit rules (a bare 2024 is 20:24), zone names, and relative items
 * (N units, ago, next/last/this, yesterday/tomorrow), with GNU's quirks --
 * a signed number right after a time is a zone offset, and a day name is
 * ignored once a date is given. Formatting is its own, with every GNU
 * conversion and flag. Options are GNU's: -d -f -I -R --rfc-3339 -r -s -u,
 * in any order.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "date_app.h"
#include "app_hooks.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#define DATE_MTIM(st) ((st)->st_mtimespec)
#else
#define DATE_MTIM(st) ((st)->st_mtim)
#endif

/* --- Formatting. --- */

typedef struct {
    struct tm tm;
    long nsec;
    time_t t;
    long gmtoff;          /* seconds east of UTC */
    const char *zone;     /* abbreviation */
} DateWhen;

static const char *const dateDays[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
static const char *const dateMonths[] = {"January", "February", "March", "April", "May", "June", "July",
                                         "August", "September", "October", "November", "December"};

/* ISO 8601 week number and week-based year. */
static int dateIsoWeek(const struct tm *tm, int *isoYear) {
    int year = tm->tm_year + 1900;
    int wday = (tm->tm_wday + 6) % 7;             /* Monday = 0 */
    int week = (tm->tm_yday - wday + 10) / 7;
    if (week < 1) {
        year--;
        int prevDays = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        week = (tm->tm_yday + prevDays - wday + 10) / 7;
    } else {
        int days = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        if (tm->tm_yday - wday + 3 >= days) {   /* Thursday of this week is next year */
            year++;
            week = 1;
        }
    }
    *isoYear = year;
    return week;
}

/* Emits one conversion: text, or a number with GNU's padding rules. */
static void dateEmit(GnuBuf *b, const char *text, bool numeric, char defPad, int defWidth, char pad, int width,
                     bool upper, bool swap) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", text);
    if (upper || swap) {
        bool allUpper = true;
        for (char *p = buf; *p; p++)
            if (islower((unsigned char)*p)) allUpper = false;
        for (char *p = buf; *p; p++)
            *p = (char)(upper ? toupper((unsigned char)*p) : (swap && allUpper ? tolower((unsigned char)*p) : toupper((unsigned char)*p)));
    }
    const char *t = buf;
    bool neg = false;
    if (numeric && *t == '-') { neg = true; t++; }
    if (numeric) while (pad == '-' && *t == '0' && t[1]) t++;
    int len = (int)strlen(t) + (neg ? 1 : 0);
    int w = width >= 0 ? width : (pad == '-' ? 0 : defWidth);
    char p = pad == '_' ? ' ' : pad == '0' ? '0' : pad == '-' ? 0 : (numeric ? defPad : ' ');
    if (!numeric && pad == '0') p = '0';
    if (p == '0' && neg) { gnuBufPut(b, "-", 1); neg = false; }
    for (int i = len; i < w && p; i++) gnuBufPut(b, &p, 1);
    if (neg) gnuBufPut(b, "-", 1);
    gnuBufPut(b, t, strlen(t));
}

static void dateFormat(GnuBuf *b, const char *fmt, const DateWhen *w) {
    const struct tm *tm = &w->tm;
    char num[64];
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { gnuBufPut(b, p, 1); continue; }
        const char *start = p++;
        char pad = 0;
        bool upper = false, swap = false;
        for (;; p++) {
            if (*p == '-' || *p == '_' || *p == '0') pad = *p;
            else if (*p == '^') upper = true;
            else if (*p == '#') swap = true;
            else break;
        }
        int width = -1;
        if (isdigit((unsigned char)*p)) {
            width = 0;
            while (isdigit((unsigned char)*p)) width = width * 10 + (*p++ - '0');
        }
        int colons = 0;
        while (*p == ':') { colons++; p++; }
        if (*p == 'E' || *p == 'O') p++;
        char c = *p;
        if (!c) { gnuBufPut(b, start, (size_t)(p - start)); break; }
#define NUM(v, dw) do { snprintf(num, sizeof(num), "%ld", (long)(v)); dateEmit(b, num, true, '0', dw, pad, width, upper, swap); } while (0)
#define SNUM(v, dw) do { snprintf(num, sizeof(num), "%ld", (long)(v)); dateEmit(b, num, true, ' ', dw, pad, width, upper, swap); } while (0)
#define TXT(s) dateEmit(b, s, false, ' ', 0, pad, width, upper, swap)
        switch (c) {
        case '%': TXT("%"); break;
        case 'a': { char t[4]; snprintf(t, 4, "%s", dateDays[tm->tm_wday]); TXT(t); break; }
        case 'A': TXT(dateDays[tm->tm_wday]); break;
        case 'b': case 'h': { char t[4]; snprintf(t, 4, "%s", dateMonths[tm->tm_mon]); TXT(t); break; }
        case 'B': TXT(dateMonths[tm->tm_mon]); break;
        case 'c': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%a %b %e %H:%M:%S %Y", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 'C': NUM((tm->tm_year + 1900) / 100, 2); break;
        case 'd': NUM(tm->tm_mday, 2); break;
        case 'D': case 'x': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%m/%d/%y", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 'e': SNUM(tm->tm_mday, 2); break;
        case 'F': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%+4Y-%m-%d", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 'g': { int y; dateIsoWeek(tm, &y); NUM(((y % 100) + 100) % 100, 2); break; }
        case 'G': { int y; dateIsoWeek(tm, &y); NUM(y, 4); break; }
        case 'H': NUM(tm->tm_hour, 2); break;
        case 'I': NUM(tm->tm_hour % 12 ? tm->tm_hour % 12 : 12, 2); break;
        case 'j': NUM(tm->tm_yday + 1, 3); break;
        case 'k': SNUM(tm->tm_hour, 2); break;
        case 'l': SNUM(tm->tm_hour % 12 ? tm->tm_hour % 12 : 12, 2); break;
        case 'm': NUM(tm->tm_mon + 1, 2); break;
        case 'M': NUM(tm->tm_min, 2); break;
        case 'n': TXT("\n"); break;
        case 'N': {
            snprintf(num, sizeof(num), "%09ld", w->nsec);
            int digits = width > 0 ? width : 9;
            if (digits < 9) num[digits] = '\0';
            else for (int i = 9; i < digits && i < 60; i++) { num[i] = '0'; num[i + 1] = '\0'; }
            gnuBufPut(b, num, strlen(num));
            break;
        }
        case 'p': TXT(tm->tm_hour < 12 ? "AM" : "PM"); break;
        case 'P': TXT(tm->tm_hour < 12 ? "am" : "pm"); break;
        case 'q': NUM(tm->tm_mon / 3 + 1, 1); break;
        case 'r': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%I:%M:%S %p", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 'R': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%H:%M", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 's': snprintf(num, sizeof(num), "%jd", (intmax_t)w->t); dateEmit(b, num, true, '0', 1, pad, width, upper, swap); break;
        case 'S': NUM(tm->tm_sec, 2); break;
        case 't': TXT("\t"); break;
        case 'T': case 'X': {
            GnuBuf sub = {NULL, 0, 0};
            dateFormat(&sub, "%H:%M:%S", w);
            TXT(sub.s ? sub.s : "");
            free(sub.s);
            break;
        }
        case 'u': NUM(tm->tm_wday ? tm->tm_wday : 7, 1); break;
        case 'U': NUM((tm->tm_yday + 7 - tm->tm_wday) / 7, 2); break;
        case 'V': { int y; NUM(dateIsoWeek(tm, &y), 2); break; }
        case 'w': NUM(tm->tm_wday, 1); break;
        case 'W': NUM((tm->tm_yday + 7 - (tm->tm_wday + 6) % 7) / 7, 2); break;
        case 'y': NUM(((tm->tm_year + 1900) % 100 + 100) % 100, 2); break;
        case 'Y': NUM(tm->tm_year + 1900, 1); break;
        case 'z': {
            long off = w->gmtoff;
            char sign = off < 0 ? '-' : '+';
            if (off < 0) off = -off;
            long h = off / 3600, m = off / 60 % 60, s = off % 60;
            if (colons == 0) snprintf(num, sizeof(num), "%c%02ld%02ld", sign, h, m);
            else if (colons == 1) snprintf(num, sizeof(num), "%c%02ld:%02ld", sign, h, m);
            else if (colons == 2) snprintf(num, sizeof(num), "%c%02ld:%02ld:%02ld", sign, h, m, s);
            else if (s) snprintf(num, sizeof(num), "%c%02ld:%02ld:%02ld", sign, h, m, s);
            else if (m) snprintf(num, sizeof(num), "%c%02ld:%02ld", sign, h, m);
            else snprintf(num, sizeof(num), "%c%02ld", sign, h);
            dateEmit(b, num, false, ' ', 0, pad, width, upper, swap);
            break;
        }
        case 'Z': TXT(w->zone ? w->zone : ""); break;
        case '+': {
            /* %+4Y from %F: a year of at least four digits */
            if (p[1] == '4' && p[2] == 'Y') {
                snprintf(num, sizeof(num), "%04d", tm->tm_year + 1900);
                gnuBufPut(b, num, strlen(num));
                p += 2;
            } else {
                gnuBufPut(b, start, (size_t)(p - start + 1));
            }
            break;
        }
        default: gnuBufPut(b, start, (size_t)(p - start + 1)); break;
        }
#undef NUM
#undef SNUM
#undef TXT
    }
}

/* Breaks time t down, in UTC or local time. */
static bool dateBreak(time_t t, long nsec, bool utc, DateWhen *w) {
    memset(w, 0, sizeof(*w));
    w->t = t;
    w->nsec = nsec;
    if (utc) {
        if (!gmtime_r(&t, &w->tm)) return false;
        w->gmtoff = 0;
        w->zone = "UTC";
    } else {
        if (!localtime_r(&t, &w->tm)) return false;
        w->gmtoff = w->tm.tm_gmtoff;
        w->zone = w->tm.tm_zone;
    }
    return true;
}

/* --- Parsing date strings: GNU's parse-datetime.y. --- */

enum { T_END, T_UNUM, T_SNUM, T_UDEC, T_SDEC, T_WORD, T_CHAR };

typedef struct {
    int kind;
    intmax_t value;
    int digits;
    long nsec;            /* decimals */
    char word[32];
    char ch;
} DateTok;

enum { W_NONE, W_MONTH, W_DAY, W_ORD, W_YEAR_UNIT, W_MONTH_UNIT, W_DAY_UNIT, W_HOUR_UNIT, W_MIN_UNIT,
       W_SEC_UNIT, W_AGO, W_SHIFT, W_MERID, W_ZONE, W_DAYZONE, W_DST, W_T };

typedef struct {
    int kind;
    int value;
} DateWord;

static DateWord dateLookup(const char *w) {
    /* Dots are ignored (a.m., p.m.); case is too. */
    char t[32];
    size_t m = 0;
    for (const char *p = w; *p && m < sizeof(t) - 1; p++)
        if (*p != '.') t[m++] = (char)toupper((unsigned char)*p);
    t[m] = '\0';
    if (!strcmp(t, "AM")) return (DateWord){W_MERID, 1};
    if (!strcmp(t, "PM")) return (DateWord){W_MERID, 2};
    static const char *const months[] = {"JANUARY", "FEBRUARY", "MARCH", "APRIL", "MAY", "JUNE", "JULY", "AUGUST",
                                         "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER"};
    for (int i = 0; i < 12; i++) {
        if (!strcmp(t, months[i]) || (strlen(t) == 3 && !strncmp(t, months[i], 3))) return (DateWord){W_MONTH, i + 1};
    }
    if (!strcmp(t, "SEPT")) return (DateWord){W_MONTH, 9};
    static const char *const days[] = {"SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"};
    for (int i = 0; i < 7; i++) {
        if (!strcmp(t, days[i]) || (strlen(t) == 3 && !strncmp(t, days[i], 3))) return (DateWord){W_DAY, i};
    }
    if (!strcmp(t, "TUES")) return (DateWord){W_DAY, 2};
    if (!strcmp(t, "WEDNES")) return (DateWord){W_DAY, 3};
    if (!strcmp(t, "THUR") || !strcmp(t, "THURS")) return (DateWord){W_DAY, 4};
    static const struct { const char *name; int kind, value; } table[] = {
        {"YEAR", W_YEAR_UNIT, 1}, {"MONTH", W_MONTH_UNIT, 1}, {"FORTNIGHT", W_DAY_UNIT, 14},
        {"WEEK", W_DAY_UNIT, 7}, {"DAY", W_DAY_UNIT, 1}, {"HOUR", W_HOUR_UNIT, 1}, {"MINUTE", W_MIN_UNIT, 1},
        {"MIN", W_MIN_UNIT, 1}, {"SECOND", W_SEC_UNIT, 1}, {"SEC", W_SEC_UNIT, 1},
        {"TOMORROW", W_SHIFT, 1}, {"YESTERDAY", W_SHIFT, -1}, {"TODAY", W_SHIFT, 0}, {"NOW", W_SHIFT, 0},
        {"LAST", W_ORD, -1}, {"THIS", W_ORD, 0}, {"NEXT", W_ORD, 1}, {"FIRST", W_ORD, 1}, {"THIRD", W_ORD, 3},
        {"FOURTH", W_ORD, 4}, {"FIFTH", W_ORD, 5}, {"SIXTH", W_ORD, 6}, {"SEVENTH", W_ORD, 7},
        {"EIGHTH", W_ORD, 8}, {"NINTH", W_ORD, 9}, {"TENTH", W_ORD, 10}, {"ELEVENTH", W_ORD, 11},
        {"TWELFTH", W_ORD, 12}, {"AGO", W_AGO, -1}, {"HENCE", W_AGO, 1}, {"DST", W_DST, 0},
        /* zones, minutes east of UTC; W_DAYZONE adds an hour */
        {"GMT", W_ZONE, 0}, {"UT", W_ZONE, 0}, {"UTC", W_ZONE, 0}, {"Z", W_ZONE, 0}, {"WET", W_ZONE, 0},
        {"WEST", W_DAYZONE, 0}, {"BST", W_DAYZONE, 0}, {"ART", W_ZONE, -180}, {"BRT", W_ZONE, -180},
        {"BRST", W_DAYZONE, -180}, {"NST", W_ZONE, -210}, {"NDT", W_DAYZONE, -210}, {"AST", W_ZONE, -240},
        {"ADT", W_DAYZONE, -240}, {"CLT", W_ZONE, -240}, {"CLST", W_DAYZONE, -240}, {"EST", W_ZONE, -300},
        {"EDT", W_DAYZONE, -300}, {"CST", W_ZONE, -360}, {"CDT", W_DAYZONE, -360}, {"MST", W_ZONE, -420},
        {"MDT", W_DAYZONE, -420}, {"PST", W_ZONE, -480}, {"PDT", W_DAYZONE, -480}, {"AKST", W_ZONE, -540},
        {"AKDT", W_DAYZONE, -540}, {"HST", W_ZONE, -600}, {"HAST", W_ZONE, -600}, {"HADT", W_DAYZONE, -600},
        {"SST", W_ZONE, -720}, {"WAT", W_ZONE, 60}, {"CET", W_ZONE, 60}, {"CEST", W_DAYZONE, 60},
        {"MET", W_ZONE, 60}, {"MEZ", W_ZONE, 60}, {"MEST", W_DAYZONE, 60}, {"MESZ", W_DAYZONE, 60},
        {"EET", W_ZONE, 120}, {"EEST", W_DAYZONE, 120}, {"CAT", W_ZONE, 120}, {"SAST", W_ZONE, 120},
        {"EAT", W_ZONE, 180}, {"MSK", W_ZONE, 180}, {"MSD", W_DAYZONE, 180}, {"IST", W_ZONE, 330},
        {"SGT", W_ZONE, 480}, {"KST", W_ZONE, 540}, {"JST", W_ZONE, 540}, {"GST", W_ZONE, 600},
        {"NZST", W_ZONE, 720}, {"NZDT", W_DAYZONE, 720},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        if (!strcmp(t, table[i].name)) return (DateWord){table[i].kind, table[i].value};
    /* Plural units. */
    size_t tl = strlen(t);
    if (tl > 1 && t[tl - 1] == 'S') {
        t[tl - 1] = '\0';
        for (size_t i = 0; i < 10; i++)
            if (!strcmp(t, table[i].name)) return (DateWord){table[i].kind, table[i].value};
    }
    if (!strcmp(t, "T")) return (DateWord){W_T, 0};
    return (DateWord){W_NONE, 0};
}

typedef struct {
    const char *in;
    /* what has been seen */
    int dates, times, days, zones, dsts, rels, timespec;
    intmax_t year;
    int yearDigits;
    int month, day, hour, minute;
    intmax_t second;
    long nsec;
    int meridian;          /* 0 24h, 1 am, 2 pm */
    int dayOrdinal, dayNumber;
    long zoneMinutes;
    intmax_t relYear, relMonth, relDay, relHour, relMinute, relSecond;
    long relNsec;
    bool fail;
} DateParse;

/* GNU's lexer: signs bind to the digits after them (and are skipped
 * otherwise), words take letters and dots, parenthesised text is a comment. */
static DateTok dateLex(DateParse *pc) {
    DateTok t;
    memset(&t, 0, sizeof(t));
    for (;;) {
        while (isspace((unsigned char)*pc->in)) pc->in++;
        const char *p = pc->in;
        char c = *p;
        if (!c) { t.kind = T_END; return t; }
        if (isdigit((unsigned char)c) || c == '-' || c == '+') {
            int sign = 0;
            if (c == '-' || c == '+') {
                sign = c == '-' ? -1 : 1;
                p++;
                while (isspace((unsigned char)*p)) p++;
                if (!isdigit((unsigned char)*p)) { pc->in = p; continue; }
            }
            intmax_t v = 0;
            int digits = 0;
            while (isdigit((unsigned char)*p)) {
                if (v > (INTMAX_MAX - 9) / 10) { pc->fail = true; t.kind = T_END; return t; }
                v = v * 10 + (*p++ - '0');
                digits++;
            }
            if ((*p == '.' || *p == ',') && isdigit((unsigned char)p[1])) {
                p++;
                long ns = 0;
                int k = 0;
                for (; isdigit((unsigned char)*p); p++, k++)
                    if (k < 9) ns = ns * 10 + (*p - '0');
                for (; k < 9; k++) ns *= 10;
                t.kind = sign ? T_SDEC : T_UDEC;
                t.value = sign < 0 ? -v : v;
                t.nsec = ns;
                if (sign < 0 && ns) { t.value -= 1; t.nsec = 1000000000 - ns; }
                pc->in = p;
                return t;
            }
            t.kind = sign ? T_SNUM : T_UNUM;
            t.value = sign < 0 ? -v : v;
            t.digits = digits;
            pc->in = p;
            return t;
        }
        if (isalpha((unsigned char)c)) {
            size_t n = 0;
            while (isalpha((unsigned char)*p) || *p == '.') {
                if (n < sizeof(t.word) - 1) t.word[n++] = *p;
                p++;
            }
            t.word[n] = '\0';
            t.kind = T_WORD;
            pc->in = p;
            return t;
        }
        if (c == '(') {
            int depth = 0;
            do {
                if (*p == '(') depth++;
                else if (*p == ')') depth--;
                else if (!*p) { pc->fail = true; t.kind = T_END; return t; }
                p++;
            } while (depth);
            pc->in = p;
            continue;
        }
        t.kind = T_CHAR;
        t.ch = c;
        pc->in = p + 1;
        return t;
    }
}

typedef struct {
    DateTok v[64];
    int n, pos;
} DateToks;

static bool dateRel(DateParse *pc, intmax_t y, intmax_t mo, intmax_t d, intmax_t h, intmax_t mi, intmax_t s, long ns,
                    int factor) {
    pc->relYear += y * factor;
    pc->relMonth += mo * factor;
    pc->relDay += d * factor;
    pc->relHour += h * factor;
    pc->relMinute += mi * factor;
    pc->relSecond += s * factor;
    pc->relNsec += ns * factor;
    pc->rels++;
    return true;
}

/* A relative unit after an optional count; returns false if `at` is none. */
static bool dateRelUnit(DateParse *pc, DateToks *ts, intmax_t count, bool counted) {
    DateTok *t = &ts->v[ts->pos];
    if (t->kind != T_WORD) return false;
    DateWord w = dateLookup(t->word);
    intmax_t n = counted ? count : 1;
    intmax_t y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    switch (w.kind) {
    case W_YEAR_UNIT: y = n; break;
    case W_MONTH_UNIT: mo = n; break;
    case W_DAY_UNIT: d = n * w.value; break;
    case W_HOUR_UNIT: h = n; break;
    case W_MIN_UNIT: mi = n; break;
    case W_SEC_UNIT: s = n; break;
    default: return false;
    }
    ts->pos++;
    int factor = 1;
    if (ts->v[ts->pos].kind == T_WORD && dateLookup(ts->v[ts->pos].word).kind == W_AGO) {
        factor = dateLookup(ts->v[ts->pos].word).value;
        ts->pos++;
    }
    return dateRel(pc, y, mo, d, h, mi, s, 0, factor);
}

static bool dateZoneOffset(DateParse *pc, intmax_t s, int digits, DateToks *ts, long *minutes) {
    /* zone_offset: tSNUMBER o_colon_minutes */
    DateTok *c = &ts->v[ts->pos];
    if (c->kind == T_CHAR && c->ch == ':' && ts->v[ts->pos + 1].kind == T_UNUM) {
        intmax_t mn = ts->v[ts->pos + 1].value;
        ts->pos += 2;
        if (s < -24 || s > 24 || mn > 59) return false;
        *minutes = (long)(s * 60 + (s < 0 ? -mn : mn));
        return true;
    }
    (void)pc;
    if (digits <= 2) {
        if (s < -24 || s > 24) return false;
        *minutes = (long)(s * 60);
    } else {
        intmax_t a = s < 0 ? -s : s;
        if (a / 100 > 24 || a % 100 > 59) return false;
        *minutes = (long)((a / 100) * 60 + a % 100) * (s < 0 ? -1 : 1);
    }
    return true;
}

static int dateMeridian(DateToks *ts) {
    DateTok *t = &ts->v[ts->pos];
    if (t->kind == T_WORD) {
        DateWord w = dateLookup(t->word);
        if (w.kind == W_MERID) { ts->pos++; return w.value; }
    }
    return 0;
}

/* The number rule: GNU's digits_to_date_time. */
static void dateDigits(DateParse *pc, intmax_t value, int digits) {
    if (pc->dates && !pc->yearDigits && !pc->rels && (pc->times || digits > 2)) {
        pc->year = value;
        pc->yearDigits = digits;
        return;
    }
    if (digits > 4) {
        pc->dates++;
        pc->day = (int)(value % 100);
        pc->month = (int)(value / 100 % 100);
        pc->year = value / 10000;
        pc->yearDigits = digits - 4;
    } else {
        pc->times++;
        if (digits <= 2) { pc->hour = (int)value; pc->minute = 0; }
        else { pc->hour = (int)(value / 100); pc->minute = (int)(value % 100); }
        pc->second = 0;
        pc->nsec = 0;
        pc->meridian = 0;
    }
}

static bool dateParseItems(DateParse *pc, DateToks *ts) {
    while (ts->v[ts->pos].kind != T_END) {
        DateTok *t = &ts->v[ts->pos];
        DateTok *n1 = &ts->v[ts->pos + 1];
        DateTok *n2 = ts->pos + 2 < ts->n ? &ts->v[ts->pos + 2] : &ts->v[ts->n - 1];
        if (t->kind == T_UNUM) {
            /* time: H:M[:S][.frac] [merid | zone offset] */
            if (n1->kind == T_CHAR && n1->ch == ':' && n2->kind == T_UNUM) {
                pc->hour = (int)t->value;
                pc->minute = (int)n2->value;
                pc->second = 0;
                pc->nsec = 0;
                ts->pos += 3;
                if (ts->v[ts->pos].kind == T_CHAR && ts->v[ts->pos].ch == ':' &&
                    (ts->v[ts->pos + 1].kind == T_UNUM || ts->v[ts->pos + 1].kind == T_UDEC)) {
                    pc->second = ts->v[ts->pos + 1].value;
                    pc->nsec = ts->v[ts->pos + 1].nsec;
                    ts->pos += 2;
                }
                pc->times++;
                pc->meridian = dateMeridian(ts);
                if (!pc->meridian && ts->v[ts->pos].kind == T_SNUM) {
                    DateTok *z = &ts->v[ts->pos++];
                    long minutes;
                    if (!dateZoneOffset(pc, z->value, z->digits, ts, &minutes)) return false;
                    pc->zoneMinutes = minutes;
                    pc->zones++;
                }
                continue;
            }
            /* date: M/D or M/D/Y or Y/M/D */
            if (n1->kind == T_CHAR && n1->ch == '/' && n2->kind == T_UNUM) {
                DateTok *a = t, *b = n2;
                ts->pos += 3;
                if (ts->v[ts->pos].kind == T_CHAR && ts->v[ts->pos].ch == '/' && ts->v[ts->pos + 1].kind == T_UNUM) {
                    DateTok *c = &ts->v[ts->pos + 1];
                    ts->pos += 2;
                    if (a->digits >= 4) {
                        pc->year = a->value; pc->yearDigits = a->digits; pc->month = (int)b->value; pc->day = (int)c->value;
                    } else {
                        pc->month = (int)a->value; pc->day = (int)b->value; pc->year = c->value; pc->yearDigits = c->digits;
                    }
                } else {
                    pc->month = (int)a->value;
                    pc->day = (int)b->value;
                }
                pc->dates++;
                continue;
            }
            /* iso_8601_date: Y -M -D */
            if (n1->kind == T_SNUM && n2->kind == T_SNUM && n1->value <= 0 && n2->value <= 0) {
                pc->year = t->value;
                pc->yearDigits = t->digits;
                pc->month = (int)-n1->value;
                pc->day = (int)-n2->value;
                pc->dates++;
                ts->pos += 3;
                /* 'T' and an ISO time may follow */
                if (ts->v[ts->pos].kind == T_WORD && dateLookup(ts->v[ts->pos].word).kind == W_T &&
                    ts->v[ts->pos + 1].kind == T_UNUM) {
                    ts->pos++;
                }
                continue;
            }
            /* N meridian */
            if (n1->kind == T_WORD && dateLookup(n1->word).kind == W_MERID) {
                pc->hour = (int)t->value;
                pc->minute = 0;
                pc->second = 0;
                pc->nsec = 0;
                pc->meridian = dateLookup(n1->word).value;
                pc->times++;
                ts->pos += 2;
                continue;
            }
            /* N month [N]: day month [year] */
            if (n1->kind == T_WORD && dateLookup(n1->word).kind == W_MONTH) {
                pc->day = (int)t->value;
                pc->month = dateLookup(n1->word).value;
                ts->pos += 2;
                if (ts->v[ts->pos].kind == T_UNUM || ts->v[ts->pos].kind == T_SNUM) {
                    intmax_t y = ts->v[ts->pos].value;
                    pc->year = y < 0 ? -y : y;
                    pc->yearDigits = ts->v[ts->pos].digits;
                    ts->pos++;
                }
                pc->dates++;
                continue;
            }
            /* N day-name: ordinal day */
            if (n1->kind == T_WORD && dateLookup(n1->word).kind == W_DAY) {
                pc->dayOrdinal = (int)t->value;
                pc->dayNumber = dateLookup(n1->word).value;
                pc->days++;
                ts->pos += 2;
                continue;
            }
            /* N unit [ago] */
            ts->pos++;
            if (dateRelUnit(pc, ts, t->value, true)) continue;
            /* hybrid: number then a signed relative item */
            dateDigits(pc, t->value, t->digits);
            continue;
        }
        if (t->kind == T_SNUM) {
            ts->pos++;
            if (dateRelUnit(pc, ts, t->value, true)) continue;
            return false;
        }
        if (t->kind == T_UDEC || t->kind == T_SDEC) {
            ts->pos++;
            DateTok *u = &ts->v[ts->pos];
            if (u->kind == T_WORD && dateLookup(u->word).kind == W_SEC_UNIT) {
                ts->pos++;
                int factor = 1;
                if (ts->v[ts->pos].kind == T_WORD && dateLookup(ts->v[ts->pos].word).kind == W_AGO) {
                    factor = dateLookup(ts->v[ts->pos].word).value;
                    ts->pos++;
                }
                dateRel(pc, 0, 0, 0, 0, 0, t->value, t->nsec, factor);
                continue;
            }
            return false;
        }
        if (t->kind == T_WORD) {
            DateWord w = dateLookup(t->word);
            switch (w.kind) {
            case W_MONTH: {
                /* month day [, year] | month -day -year */
                pc->month = w.value;
                ts->pos++;
                DateTok *a = &ts->v[ts->pos];
                if (a->kind == T_UNUM) {
                    pc->day = (int)a->value;
                    ts->pos++;
                    if (ts->v[ts->pos].kind == T_CHAR && ts->v[ts->pos].ch == ',' && ts->v[ts->pos + 1].kind == T_UNUM) {
                        pc->year = ts->v[ts->pos + 1].value;
                        pc->yearDigits = ts->v[ts->pos + 1].digits;
                        ts->pos += 2;
                    }
                } else if (a->kind == T_SNUM && ts->v[ts->pos + 1].kind == T_SNUM) {
                    pc->day = (int)-a->value;
                    pc->year = -ts->v[ts->pos + 1].value;
                    pc->yearDigits = ts->v[ts->pos + 1].digits;
                    ts->pos += 2;
                } else {
                    return false;
                }
                pc->dates++;
                continue;
            }
            case W_DAY:
                pc->dayOrdinal = 0;
                pc->dayNumber = w.value;
                pc->days++;
                ts->pos++;
                if (ts->v[ts->pos].kind == T_CHAR && ts->v[ts->pos].ch == ',') ts->pos++;
                continue;
            case W_ORD: {
                ts->pos++;
                DateTok *u = &ts->v[ts->pos];
                if (u->kind == T_WORD && dateLookup(u->word).kind == W_DAY) {
                    pc->dayOrdinal = w.value;
                    pc->dayNumber = dateLookup(u->word).value;
                    pc->days++;
                    ts->pos++;
                    continue;
                }
                if (dateRelUnit(pc, ts, w.value, true)) continue;
                return false;
            }
            case W_YEAR_UNIT: case W_MONTH_UNIT: case W_DAY_UNIT: case W_HOUR_UNIT: case W_MIN_UNIT: case W_SEC_UNIT:
                if (dateRelUnit(pc, ts, 1, false)) continue;
                return false;
            case W_SHIFT:
                ts->pos++;
                dateRel(pc, 0, 0, w.value, 0, 0, 0, 0, 1);
                continue;
            case W_ZONE: case W_DAYZONE: case W_T: {
                if (w.kind == W_T) return false;
                long minutes = w.value + (w.kind == W_DAYZONE ? 60 : 0);
                ts->pos++;
                if (w.kind == W_ZONE && ts->v[ts->pos].kind == T_WORD && dateLookup(ts->v[ts->pos].word).kind == W_DST) {
                    minutes += 60;
                    ts->pos++;
                } else if (w.kind == W_ZONE && ts->v[ts->pos].kind == T_SNUM) {
                    DateTok *z = &ts->v[ts->pos];
                    ts->pos++;
                    if (dateRelUnit(pc, ts, z->value, true)) {
                        /* zone relunit_snumber */
                    } else {
                        long off;
                        if (!dateZoneOffset(pc, z->value, z->digits, ts, &off)) return false;
                        minutes += off;
                    }
                }
                pc->zoneMinutes = minutes;
                pc->zones++;
                continue;
            }
            default:
                return false;
            }
        }
        return false;
    }
    return true;
}

/* Parses `s` relative to `now`; the result in *out (seconds, nanoseconds). */
static bool dateParse(const char *s, struct timespec now, bool utc, struct timespec *out) {
    DateParse pc;
    memset(&pc, 0, sizeof(pc));
    pc.in = s;
    while (isspace((unsigned char)*pc.in)) pc.in++;
    if (*pc.in == '@') {
        pc.in++;
        DateTok t = dateLex(&pc);
        if (pc.fail || (t.kind != T_UNUM && t.kind != T_SNUM && t.kind != T_UDEC && t.kind != T_SDEC)) return false;
        if (dateLex(&pc).kind != T_END) return false;
        out->tv_sec = (time_t)t.value;
        out->tv_nsec = t.nsec;
        return true;
    }
    DateToks ts;
    memset(&ts, 0, sizeof(ts));
    for (;;) {
        DateTok t = dateLex(&pc);
        if (pc.fail || ts.n >= 62) return false;
        ts.v[ts.n++] = t;
        if (t.kind == T_END) break;
    }
    ts.v[ts.n] = ts.v[ts.n - 1];
    struct tm tm;
    time_t base = now.tv_sec;
    if (!(utc ? gmtime_r(&base, &tm) : localtime_r(&base, &tm))) return false;
    pc.year = tm.tm_year + 1900;
    pc.yearDigits = 0;
    pc.month = tm.tm_mon + 1;
    pc.day = tm.tm_mday;
    pc.hour = tm.tm_hour;
    pc.minute = tm.tm_min;
    pc.second = tm.tm_sec;
    pc.nsec = now.tv_nsec;
    if (!dateParseItems(&pc, &ts)) return false;
    if (pc.times > 1 || pc.dates > 1 || pc.days > 1 || pc.zones > 1) return false;

    struct tm t0;
    memset(&t0, 0, sizeof(t0));
    intmax_t year = pc.year;
    if (pc.yearDigits == 2) year += year < 69 ? 2000 : 1900;
    t0.tm_year = (int)(year - 1900);
    t0.tm_mon = pc.month - 1;
    t0.tm_mday = pc.day;
    if (pc.times || (pc.rels && !pc.dates && !pc.days)) {
        int h = pc.hour;
        if (pc.meridian) {
            if (h < 1 || h > 12) return false;
            h = h % 12 + (pc.meridian == 2 ? 12 : 0);
        } else if (h < 0 || h > 23) {
            return false;
        }
        if (pc.minute < 0 || pc.minute > 59 || pc.second < 0 || pc.second > 60) return false;
        t0.tm_hour = h;
        t0.tm_min = pc.minute;
        t0.tm_sec = (int)pc.second;
    } else {
        pc.nsec = 0;
    }
    if (pc.month < 1 || pc.month > 12 || pc.day < 1 || pc.day > 31) return false;
    t0.tm_isdst = -1;
    /* Arithmetic in the zone the string names, else -u's UTC or local. */
    bool fieldsUtc = utc || pc.zones;
    struct tm tm1 = t0;
    time_t start = fieldsUtc ? timegm(&tm1) : mktime(&tm1);
    if (start == (time_t)-1 && !(tm1.tm_year == 69 && tm1.tm_mon == 11 && tm1.tm_mday == 31)) return false;
    /* GNU's mktime_ok: the fields must survive normalisation, which rejects
     * 2024-02-30 and a local time inside a daylight-saving gap. */
    if (tm1.tm_mday != t0.tm_mday || tm1.tm_mon != t0.tm_mon || tm1.tm_year != t0.tm_year ||
        tm1.tm_hour != t0.tm_hour || tm1.tm_min != t0.tm_min || tm1.tm_sec != t0.tm_sec)
        return false;
    if (pc.days && !pc.dates) {
        tm1.tm_mday += ((pc.dayNumber - tm1.tm_wday + 7) % 7 +
                        7 * (pc.dayOrdinal - (0 < pc.dayOrdinal && tm1.tm_wday != pc.dayNumber)));
        tm1.tm_isdst = -1;
        start = fieldsUtc ? timegm(&tm1) : mktime(&tm1);
    }
    if (pc.relYear || pc.relMonth || pc.relDay) {
        struct tm tm2 = tm1;
        tm2.tm_year += (int)pc.relYear;
        tm2.tm_mon += (int)pc.relMonth;
        tm2.tm_mday += (int)pc.relDay;
        tm2.tm_isdst = -1;
        start = fieldsUtc ? timegm(&tm2) : mktime(&tm2);
    }
    if (pc.zones) start -= (time_t)pc.zoneMinutes * 60;
    long ns = pc.nsec + pc.relNsec;
    intmax_t secs = (intmax_t)start + pc.relHour * 3600 + pc.relMinute * 60 + pc.relSecond;
    while (ns < 0) { ns += 1000000000; secs--; }
    while (ns >= 1000000000) { ns -= 1000000000; secs++; }
    out->tv_sec = (time_t)secs;
    out->tv_nsec = ns;
    return true;
}

/* --- The command. --- */

/* For touch -d: the parse-datetime grammar, relative to `now`, in local
 * time. */
bool smallclueParseDatetime(const char *s, struct timespec now, struct timespec *out) {
    return dateParse(s, now, false, out);
}

static int dateTry(void) {
    fputs("Try 'date --help' for more information.\n", stderr);
    return 1;
}

static void dateUsage(void) {
    fputs("Usage: date [OPTION]... [+FORMAT]\n"
          "  or:  date [-u|--utc|--universal] [MMDDhhmm[[CC]YY][.ss]]\n"
          "Display date and time in the given FORMAT.\n"
          "With -s, or with [MMDDhhmm[[CC]YY][.ss]], set the date and time.\n\n"
          "  -d, --date=STRING          display time described by STRING, not 'now'\n"
          "  -f, --file=DATEFILE        like --date; once for each line of DATEFILE\n"
          "  -I[FMT], --iso-8601[=FMT]  output date/time in ISO 8601 format.\n"
          "                               FMT='date' for date only (the default),\n"
          "                               'hours', 'minutes', 'seconds', or 'ns'\n"
          "  -R, --rfc-email            output date and time in RFC 5322 format.\n"
          "      --rfc-3339=FMT         output date/time in RFC 3339 format.\n"
          "                               FMT='date', 'seconds', or 'ns'\n"
          "  -r, --reference=FILE       display the last modification time of FILE\n"
          "  -s, --set=STRING           set time described by STRING\n"
          "  -u, --utc, --universal     print or set Coordinated Universal Time (UTC)\n"
          "      --help        display this help and exit\n"
          "      --version     output version information and exit\n",
          stdout);
}

static bool dateArgmatch(const char *opt, const char *val, const char *const *valid, int n, int *out) {
    for (int i = 0; i < n; i++)
        if (!strcmp(val, valid[i])) { *out = i; return true; }
    /* unambiguous prefix */
    int found = -1;
    for (int i = 0; i < n; i++) {
        if (!strncmp(valid[i], val, strlen(val))) {
            if (found >= 0) { found = -2; break; }
            found = i;
        }
    }
    if (found >= 0 && *val) { *out = found; return true; }
    char q[256], q2[64];
    fprintf(stderr, "date: invalid argument %s for %s\nValid arguments are:\n", gnuQuoteLocale(val, q, sizeof(q)),
            gnuQuoteLocale(opt, q2, sizeof(q2)));
    for (int i = 0; i < n; i++) fprintf(stderr, "  - %s\n", gnuQuoteLocale(valid[i], q, sizeof(q)));
    return false;
}

static bool datePrint(const char *fmt, struct timespec when, bool utc) {
    DateWhen w;
    if (!dateBreak(when.tv_sec, when.tv_nsec, utc, &w)) {
        fprintf(stderr, "date: time %jd is out of range\n", (intmax_t)when.tv_sec);
        return false;
    }
    GnuBuf b = {NULL, 0, 0};
    gnuBufPut(&b, "", 0);
    dateFormat(&b, fmt, &w);
    fwrite(b.s, 1, b.n, stdout);
    putchar('\n');
    free(b.s);
    return true;
}

/* MMDDhhmm[[CC]YY][.ss], the POSIX setting operand. */
static bool dateSetOperand(const char *s, bool utc, struct timespec *out) {
    size_t len = strlen(s);
    const char *dot = strchr(s, '.');
    size_t main = dot ? (size_t)(dot - s) : len;
    if (!(main == 8 || main == 10 || main == 12)) return false;
    for (size_t i = 0; i < main; i++) if (!isdigit((unsigned char)s[i])) return false;
    if (dot && (strlen(dot) != 3 || !isdigit((unsigned char)dot[1]) || !isdigit((unsigned char)dot[2]))) return false;
    struct tm tm;
    time_t now = time(NULL);
    if (!(utc ? gmtime_r(&now, &tm) : localtime_r(&now, &tm))) return false;
    int v[6];
    for (size_t i = 0; i < main / 2; i++) v[i] = (s[2 * i] - '0') * 10 + (s[2 * i + 1] - '0');
    tm.tm_mon = v[0] - 1;
    tm.tm_mday = v[1];
    tm.tm_hour = v[2];
    tm.tm_min = v[3];
    if (main == 10) tm.tm_year = v[4] < 69 ? v[4] + 100 : v[4];
    if (main == 12) tm.tm_year = v[4] * 100 + v[5] - 1900;
    tm.tm_sec = dot ? (dot[1] - '0') * 10 + (dot[2] - '0') : 0;
    tm.tm_isdst = -1;
    struct tm check = tm;
    time_t t = utc ? timegm(&check) : mktime(&check);
    if (t == (time_t)-1 || check.tm_mon != tm.tm_mon || check.tm_mday != tm.tm_mday || check.tm_hour != tm.tm_hour)
        return false;
    out->tv_sec = t;
    out->tv_nsec = 0;
    return true;
}

static bool dateSet(struct timespec ts) {
#if defined(PSCAL_TARGET_IOS)
    (void)ts;
    fputs("date: cannot set date: Operation not permitted\n", stderr);
    return false;
#else
    if (clock_settime(CLOCK_REALTIME, &ts) != 0) {
        fprintf(stderr, "date: cannot set date: %s\n", strerror(errno));
        return false;
    }
    return true;
#endif
}

int smallclueDateCommand(int argc, char **argv) {
    const char *dateStr = NULL, *setStr = NULL, *refFile = NULL, *dateFile = NULL;
    const char *format = NULL;
    char isoFmt[64];
    bool utc = false;
    int formats = 0, sources = 0;
    char **operands = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nops = 0, status = 1;
    if (!operands) return 1;

    static const struct { const char *name; char c; int arg; } longs[] = {
        {"date", 'd', 1}, {"debug", 1, 0}, {"file", 'f', 1}, {"iso-8601", 'I', 2}, {"reference", 'r', 1},
        {"resolution", 2, 0}, {"rfc-822", 'R', 0}, {"rfc-2822", 'R', 0}, {"rfc-email", 'R', 0},
        {"rfc-3339", 3, 1}, {"set", 's', 1}, {"uct", 'u', 0}, {"utc", 'u', 0}, {"universal", 'u', 0},
        {"help", 4, 0}, {"version", 5, 0},
    };
    bool endOfOptions = false;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            operands[nops++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        char c = 0;
        const char *val = NULL;
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            int m = -1, matches = 0;
            for (int k = 0; k < (int)(sizeof(longs) / sizeof(longs[0])); k++) {
                if (strncmp(longs[k].name, opt, len)) continue;
                if (strlen(longs[k].name) == len) { m = k; matches = 1; break; }
                if (m >= 0 && longs[m].c == longs[k].c) continue;
                m = k;
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "date: option '%s' is ambiguous\n" : "date: unrecognized option '%s'\n", arg);
                status = dateTry();
                goto done;
            }
            c = longs[m].c;
            if (eq) {
                if (!longs[m].arg) {
                    fprintf(stderr, "date: option '--%s' doesn't allow an argument\n", longs[m].name);
                    status = dateTry();
                    goto done;
                }
                val = eq + 1;
            } else if (longs[m].arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "date: option '--%s' requires an argument\n", longs[m].name);
                    status = dateTry();
                    goto done;
                }
                val = argv[++i];
            }
            if (c == 'I' && !val) val = "";
        } else {
            for (const char *p = arg + 1; *p; p++) {
                c = *p;
                if (strchr("dfrs", c)) {
                    val = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
                    if (!val) {
                        fprintf(stderr, "date: option requires an argument -- '%c'\n", c);
                        status = dateTry();
                        goto done;
                    }
                    break;
                }
                if (c == 'I') {
                    val = p + 1;
                    break;
                }
                if (c == 'R' || c == 'u') {
                    if (c == 'u') utc = true;
                    else { snprintf(isoFmt, sizeof(isoFmt), "%%a, %%d %%b %%Y %%H:%%M:%%S %%z"); format = isoFmt; formats++; }
                    continue;
                }
                fprintf(stderr, "date: invalid option -- '%c'\n", c);
                status = dateTry();
                goto done;
            }
            if (c == 'R' || c == 'u') continue;
        }
        /* Repeating one of these keeps the last; mixing two is an error. */
        switch (c) {
        case 'd': sources += !dateStr; dateStr = val; break;
        case 'f': sources += !dateFile; dateFile = val; break;
        case 'r': sources += !refFile; refFile = val; break;
        case 's': setStr = val; break;
        case 'u': utc = true; break;
        case 'R':
            snprintf(isoFmt, sizeof(isoFmt), "%%a, %%d %%b %%Y %%H:%%M:%%S %%z");
            format = isoFmt;
            formats++;
            break;
        case 'I': {
            static const char *const kinds[] = {"hours", "minutes", "date", "seconds", "ns"};
            static const char *const fmts[] = {"%Y-%m-%dT%H%:z", "%Y-%m-%dT%H:%M%:z", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%:z",
                                               "%Y-%m-%dT%H:%M:%S,%N%:z"};
            int k = 2;
            if (val && *val && !dateArgmatch("--iso-8601", val, kinds, 5, &k)) { status = dateTry(); goto done; }
            snprintf(isoFmt, sizeof(isoFmt), "%s", fmts[k]);
            format = isoFmt;
            formats++;
            break;
        }
        case 3: {
            static const char *const kinds[] = {"date", "seconds", "ns"};
            static const char *const fmts[] = {"%Y-%m-%d", "%Y-%m-%d %H:%M:%S%:z", "%Y-%m-%d %H:%M:%S.%N%:z"};
            int k;
            if (!dateArgmatch("--rfc-3339", val, kinds, 3, &k)) { status = dateTry(); goto done; }
            snprintf(isoFmt, sizeof(isoFmt), "%s", fmts[k]);
            format = isoFmt;
            formats++;
            break;
        }
        case 4: dateUsage(); status = 0; goto done;
        case 5: puts("date (SmallCLUE) 9.4"); status = 0; goto done;
        default: break;
        }
    }

    char q[512];
    const char *setOperand = NULL;
    for (int k = 0; k < nops; k++) {
        if (operands[k][0] == '+') {
            if (format && formats == 0) {
                fprintf(stderr, "date: extra operand %s\n", gnuQuoteLocale(operands[k], q, sizeof(q)));
                status = dateTry();
                goto done;
            }
            if (formats) {
                fputs("date: multiple output formats specified\n", stderr);
                goto done;
            }
            format = operands[k] + 1;
        } else if (!setOperand && k == 0 && !format) {
            setOperand = operands[k];
        } else {
            fprintf(stderr, "date: extra operand %s\n", gnuQuoteLocale(operands[k], q, sizeof(q)));
            status = dateTry();
            goto done;
        }
    }
    if (formats > 1) {
        fputs("date: multiple output formats specified\n", stderr);
        goto done;
    }
    if (sources > 1) {
        fputs("date: the options to specify dates for printing are mutually exclusive\n", stderr);
        status = dateTry();
        goto done;
    }
    if (setStr && sources) {
        fputs("date: the options to print and set the time may not be used together\n", stderr);
        status = dateTry();
        goto done;
    }
    if (!format) format = "%a %b %e %H:%M:%S %Z %Y";

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    /* -u is the zone for parsing too, as GNU sets TZ=UTC0; here every
     * conversion takes `utc` instead of touching the environment. */

    if (dateFile) {
        FILE *fp = strcmp(dateFile, "-") ? smallclueAppOpenRead(dateFile) : stdin;
        if (!fp) {
            fprintf(stderr, "date: %s: %s\n", dateFile, strerror(errno));
            goto done;
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        status = 0;
        while ((n = getline(&line, &cap, fp)) >= 0) {
            if (n && line[n - 1] == '\n') line[--n] = '\0';
            struct timespec when;
            if (!dateParse(line, now, utc, &when)) {
                fprintf(stderr, "date: invalid date %s\n", gnuQuoteLocale(line, q, sizeof(q)));
                status = 1;
                continue;
            }
            if (!datePrint(format, when, utc)) status = 1;
        }
        free(line);
        if (fp != stdin) fclose(fp);
        goto done;
    }

    struct timespec when = now;
    if (refFile) {
        struct stat st;
        if (stat(refFile, &st) != 0) {
            fprintf(stderr, "date: %s: %s\n", refFile, strerror(errno));
            goto done;
        }
        when = DATE_MTIM(&st);
    } else if (dateStr || setStr) {
        const char *s = setStr ? setStr : dateStr;
        if (!dateParse(s, now, utc, &when)) {
            fprintf(stderr, "date: invalid date %s\n", gnuQuoteLocale(s, q, sizeof(q)));
            goto done;
        }
    } else if (setOperand) {
        if (!dateSetOperand(setOperand, utc, &when)) {
            fprintf(stderr, "date: invalid date %s\n", gnuQuoteLocale(setOperand, q, sizeof(q)));
            goto done;
        }
    }
    status = 0;
    if ((setStr || setOperand) && !dateSet(when)) status = 1;
    if (!datePrint(format, when, utc)) status = 1;

done:
    free(operands);
    if (fflush(stdout) != 0 && status == 0) status = 1;
    return status;
}
