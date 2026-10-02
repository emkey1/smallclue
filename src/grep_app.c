/*
 * grep: print lines that match patterns, compatible with GNU grep 3.11.
 *
 * The grep this replaces had no context (-A/-B/-C), -b, -T, -z, -Z, -P,
 * --include/--exclude/--exclude-dir, --label or binary-file handling, read
 * its options only before the pattern, and printed none of GNU's messages.
 * This is GNU's: options anywhere (-- ends them), -G/-E/-F/-P, -e/-f with
 * newline-separated patterns, -i -v -w (GNU's shorter-match retry) -x, -c
 * -l -L -m -o -q -s, -b -H -h -n -T -Z --label, context with "--"
 * separators, -z, -r/-R with --include/--exclude/--exclude-dir, binary
 * files (NUL or, in UTF-8, an encoding error: "binary file matches" on
 * stderr; -a, -I, --binary-files), --color with GREP_COLORS, GNU 3.8's
 * warnings for stray backslashes, and the exit statuses (2 for trouble,
 * unless -q found a match).
 *
 * Patterns compile with the host's regcomp; gnu_regex.h gives it GNU's
 * extensions. -P is a translation of the common Perl subset into that:
 * \d \w \s \h and their negations (in brackets too), \b, \A \z, (?:),
 * a leading (?i), \Q...\E, \xHH, and \K, a leading (?<=...) and a trailing
 * (?=...) for -o. Other lookarounds are refused.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "grep_app.h"
#include "app_hooks.h"
#include "gnu_regex.h"
#include "gnu_util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef REG_STARTEND
#error "grep needs regexec's REG_STARTEND"
#endif

typedef struct {
    regex_t re;
    bool empty;           /* the empty pattern: matches at every position */
    int prefixGroup;      /* -P \K or (?<=): the match starts after this group */
    int bodyGroup;        /* -P: the reported match is this group (0: whole) */
} GrepPat;

typedef struct {
    char **v;
    size_t n;
} GrepList;

typedef struct {
    char *text;
    size_t len;
    intmax_t lineno;
    intmax_t offset;
} GrepHeld;

typedef struct {
    /* options */
    char mode;            /* 'G', 'E', 'F', 'P' */
    bool icase, invert, word, line, count, listWith, listWithout, quiet, noMessages, only;
    bool byteOffset, lineNumber, tab, nullName, lineBuffered;
    int numberWidth;      /* -T: the digits of the file's size, 19 when unknown */
    int withName;         /* -1 by number of files, 0 -h, 1 -H */
    const char *label;
    intmax_t maxCount;    /* -1: none */
    intmax_t before, after;
    const char *groupSep; /* NULL: --no-group-separator */
    char binary;          /* 'b' binary (default), 't' -a, 'w' -I */
    char directories;     /* 'r' read, 's' skip, 'R' recurse */
    char devices;         /* 'r' read, 's' skip */
    bool recursive, deref;
    GrepList include, exclude, excludeDir;
    bool color;
    char eol;             /* '\n', or '\0' with -z */
    /* colours */
    const char *cMatchSel, *cMatchCx, *cSel, *cCx, *cFile, *cLine, *cByte, *cSep;
    bool colorNe;
    /* patterns */
    GrepPat *pats;
    size_t npats;
    /* state */
    bool anyMatch, error, done, everOutput;
    bool utf8;
} Grep;

static const char *grepName(const char *name) {
    return strcmp(name, "-") ? name : "(standard input)";
}

/* --- Colours. --- */

static void grepSgrStart(Grep *g, const char *c) {
    if (g->color && c && *c) printf("\33[%sm%s", c, g->colorNe ? "" : "\33[K");
}

static void grepSgrEnd(Grep *g, const char *c) {
    if (g->color && c && *c) printf("\33[m%s", g->colorNe ? "" : "\33[K");
}

static void grepParseColors(Grep *g) {
    g->cMatchSel = g->cMatchCx = "01;31";
    g->cSel = g->cCx = "";
    g->cFile = "35";
    g->cLine = g->cByte = "32";
    g->cSep = "36";
    const char *old = getenv("GREP_COLOR");
    if (old && *old) {
        fprintf(stderr, "grep: warning: GREP_COLOR='%s' is deprecated; use GREP_COLORS='mt=%s'\n", old, old);
        g->cMatchSel = g->cMatchCx = old;
    }
    const char *env = getenv("GREP_COLORS");
    if (!env || !*env) return;
    /* Parsed in place into owned strings that live as long as the command. */
    static __thread char buf[512];
    snprintf(buf, sizeof(buf), "%s", env);
    char *save = NULL;
    bool rv = false;
    for (char *item = strtok_r(buf, ":", &save); item; item = strtok_r(NULL, ":", &save)) {
        char *eq = strchr(item, '=');
        const char *val = eq ? eq + 1 : NULL;
        if (eq) *eq = '\0';
        if (!strcmp(item, "mt") && val) g->cMatchSel = g->cMatchCx = val;
        else if (!strcmp(item, "ms") && val) g->cMatchSel = val;
        else if (!strcmp(item, "mc") && val) g->cMatchCx = val;
        else if (!strcmp(item, "sl") && val) g->cSel = val;
        else if (!strcmp(item, "cx") && val) g->cCx = val;
        else if (!strcmp(item, "fn") && val) g->cFile = val;
        else if (!strcmp(item, "ln") && val) g->cLine = val;
        else if (!strcmp(item, "bn") && val) g->cByte = val;
        else if (!strcmp(item, "se") && val) g->cSep = val;
        else if (!strcmp(item, "ne")) g->colorNe = true;
        else if (!strcmp(item, "rv")) rv = true;
    }
    if (rv && g->invert) {
        const char *t = g->cSel;
        g->cSel = g->cCx;
        g->cCx = t;
    }
}

/* --- Patterns. --- */

/* Copies a bracket expression [...] starting at p; returns its end. */
static const char *grepBracket(GnuBuf *b, const char *p) {
    const char *q = p + 1;
    if (*q == '^') q++;
    if (*q == ']') q++;
    while (*q && *q != ']') {
        if (*q == '[' && (q[1] == ':' || q[1] == '.' || q[1] == '=')) {
            const char *close = strchr(q + 2, q[1]);
            q = close && close[1] == ']' ? close + 2 : q + 1;
        } else {
            q++;
        }
    }
    if (*q == ']') q++;
    gnuBufPut(b, p, (size_t)(q - p));
    return q;
}

/* -G and -E: a backslash that means nothing to GNU leaves the character
 * standing for itself. The host's enhanced syntax would otherwise read some
 * of them (\d) as something GNU does not. */
static char *grepTranslateGnu(const char *pat, bool ere) {
    GnuBuf b = {NULL, 0, 0};
    gnuBufPut(&b, "", 0);
    for (const char *p = pat; *p;) {
        if (*p == '[') {
            p = grepBracket(&b, p);
            continue;
        }
        if (*p == '\\' && p[1]) {
            char c = p[1];
            bool keep = strchr("123456789`'<>bBwWsS", c) || strchr(".[]*^$\\", c) ||
                        (ere ? strchr("(){}|+?", c) != NULL : strchr("(){}|+?", c) != NULL);
            if (keep) {
                gnuBufPut(&b, p, 2);
            } else {
                gnuBufPutc(&b, c);
            }
            p += 2;
            continue;
        }
        gnuBufPutc(&b, *p++);
    }
    return b.s;
}

/* -F: every character literal, as a basic expression. */
static char *grepTranslateFixed(const char *pat) {
    GnuBuf b = {NULL, 0, 0};
    gnuBufPut(&b, "", 0);
    for (const char *p = pat; *p; p++) {
        if (strchr(".[]*^$\\", *p)) gnuBufPutc(&b, '\\');
        gnuBufPutc(&b, *p);
    }
    return b.s;
}

/* Appends a Perl class escape (\d \w \s \h and negations) as bracket
 * content; inBracket says whether we are already inside [...]. */
static bool grepPerlClass(GnuBuf *b, char c, bool inBracket) {
    const char *pos = NULL, *neg = NULL;
    switch (c) {
    case 'd': pos = "0-9"; break;
    case 'D': neg = "0-9"; break;
    case 'w': pos = "[:alnum:]_"; break;
    case 'W': neg = "[:alnum:]_"; break;
    case 's': pos = "[:space:]"; break;
    case 'S': neg = "[:space:]"; break;
    case 'h': pos = " \t"; break;
    case 'H': neg = " \t"; break;
    default: return false;
    }
    if (inBracket) {
        if (neg) return false;   /* [^...] inside a set has no POSIX spelling */
        gnuBufPut(b, pos, strlen(pos));
        return true;
    }
    gnuBufPut(b, neg ? "[^" : "[", neg ? 2 : 1);
    gnuBufPut(b, neg ? neg : pos, strlen(neg ? neg : pos));
    gnuBufPutc(b, ']');
    return true;
}

static void grepPerlLiteral(GnuBuf *b, char c) {
    if (strchr(".[]*^$\\(){}|+?", c)) gnuBufPutc(b, '\\');
    gnuBufPutc(b, c);
}

/* -P into the host's extended syntax. Sets *icase for a leading (?i),
 * *prefixGroup when a \K or leading (?<=...) splits off a prefix, and
 * *bodyGroup when the reported match is a group. NULL after a message. */
static char *grepTranslatePerl(const char *pat, bool *icase, int *prefixGroup, int *bodyGroup) {
    GnuBuf b = {NULL, 0, 0};
    gnuBufPut(&b, "", 0);
    const char *p = pat;
    *prefixGroup = *bodyGroup = 0;
    if (!strncmp(p, "(?i)", 4)) {
        *icase = true;
        p += 4;
    }
    /* A leading lookbehind is a prefix that is matched but not reported. */
    bool split = false;
    GnuBuf prefix = {NULL, 0, 0};
    gnuBufPut(&prefix, "", 0);
    GnuBuf *out = &b;
    if (!strncmp(p, "(?<=", 4)) {
        split = true;
        out = &prefix;
        p += 4;
    }
    int depth = 0, lookDepth = split ? 1 : 0;
    const char *lookahead = NULL;
    while (*p) {
        if (*p == '\\' && p[1]) {
            char c = p[1];
            if (c == 'K') {
                if (split) goto unsupported;
                split = true;
                /* everything so far was the prefix */
                gnuBufPut(&prefix, b.s, b.n);
                b.n = 0;
                b.s[0] = '\0';
                p += 2;
                continue;
            }
            if (c == 'Q') {
                p += 2;
                while (*p && !(p[0] == '\\' && p[1] == 'E')) grepPerlLiteral(out, *p++);
                if (*p) p += 2;
                continue;
            }
            if (c == 'E') { p += 2; continue; }
            if (grepPerlClass(out, c, false)) { p += 2; continue; }
            if (c == 'A') { gnuBufPutc(out, '^'); p += 2; continue; }
            if (c == 'z' || c == 'Z') { gnuBufPutc(out, '$'); p += 2; continue; }
            if (c == 't') { gnuBufPutc(out, '\t'); p += 2; continue; }
            if (c == 'n') { gnuBufPutc(out, '\n'); p += 2; continue; }
            if (c == 'r') { gnuBufPutc(out, '\r'); p += 2; continue; }
            if (c == 'e') { gnuBufPutc(out, '\33'); p += 2; continue; }
            if (c == 'x') {
                const char *q = p + 2;
                int v = 0, k = 0;
                if (*q == '{') {
                    q++;
                    while (isxdigit((unsigned char)*q)) { v = v * 16 + (isdigit((unsigned char)*q) ? *q - '0' : (tolower(*q) - 'a' + 10)); q++; }
                    if (*q == '}') q++;
                } else {
                    while (k < 2 && isxdigit((unsigned char)*q)) { v = v * 16 + (isdigit((unsigned char)*q) ? *q - '0' : (tolower(*q) - 'a' + 10)); q++; k++; }
                }
                grepPerlLiteral(out, (char)v);
                p = q;
                continue;
            }
            if (strchr("bB123456789", c) || ispunct((unsigned char)c)) {
                gnuBufPut(out, p, 2);
                p += 2;
                continue;
            }
            gnuBufPutc(out, c);
            p += 2;
            continue;
        }
        if (*p == '[') {
            /* Perl escapes inside a set. */
            const char *q = p + 1;
            gnuBufPutc(out, '[');
            if (*q == '^') gnuBufPutc(out, *q++);
            bool closeLiteral = false, dashLiteral = false;
            GnuBuf body = {NULL, 0, 0};
            gnuBufPut(&body, "", 0);
            if (*q == ']') { closeLiteral = true; q++; }
            while (*q && *q != ']') {
                if (*q == '\\' && q[1]) {
                    char c = q[1];
                    if (grepPerlClass(&body, c, true)) { q += 2; continue; }
                    if (c == ']') closeLiteral = true;
                    else if (c == '-') dashLiteral = true;
                    else if (c == 't') gnuBufPutc(&body, '\t');
                    else if (c == 'n') gnuBufPutc(&body, '\n');
                    else gnuBufPutc(&body, c);
                    q += 2;
                    continue;
                }
                if (*q == '[' && q[1] == ':') {
                    const char *close = strstr(q + 2, ":]");
                    if (close) {
                        gnuBufPut(&body, q, (size_t)(close + 2 - q));
                        q = close + 2;
                        continue;
                    }
                }
                gnuBufPutc(&body, *q++);
            }
            if (closeLiteral) gnuBufPutc(out, ']');
            gnuBufPut(out, body.s, body.n);
            if (dashLiteral) gnuBufPutc(out, '-');
            gnuBufPutc(out, ']');
            free(body.s);
            if (*q == ']') q++;
            p = q;
            continue;
        }
        if (*p == '(' && p[1] == '?') {
            if (p[2] == ':') { gnuBufPutc(out, '('); depth++; p += 3; continue; }
            if (p[2] == '=' && depth == 0 && !lookahead) {
                /* A trailing lookahead: matched, not reported. */
                lookahead = p;
                break;
            }
            goto unsupported;
        }
        if (*p == '(') depth++;
        if (*p == ')') {
            if (lookDepth && depth == 0) {
                /* the end of the leading lookbehind */
                lookDepth = 0;
                out = &b;
                p++;
                continue;
            }
            depth--;
        }
        gnuBufPutc(out, *p++);
    }
    if (lookahead) {
        /* (?=X) at the end: X must follow, so it joins the regex as a group
         * after the body, which is what gets reported. */
        const char *q = lookahead + 3;
        int d = 1;
        const char *end = q;
        while (*end && d) {
            if (*end == '\\' && end[1]) { end += 2; continue; }
            if (*end == '(') d++;
            if (*end == ')') d--;
            if (d) end++;
        }
        if (*end != ')' || end[1] != '\0') goto unsupported;
        char *inner = strndup(q, (size_t)(end - q));
        bool ic = false;
        int pg, bg;
        char *tr = inner ? grepTranslatePerl(inner, &ic, &pg, &bg) : NULL;
        free(inner);
        if (!tr) { free(b.s); free(prefix.s); return NULL; }
        GnuBuf all = {NULL, 0, 0};
        gnuBufPut(&all, "", 0);
        int group = 1;
        if (split) {
            gnuBufPutc(&all, '(');
            gnuBufPut(&all, prefix.s, prefix.n);
            gnuBufPutc(&all, ')');
            *prefixGroup = group++;
        }
        gnuBufPutc(&all, '(');
        gnuBufPut(&all, b.s, b.n);
        gnuBufPutc(&all, ')');
        *bodyGroup = group;
        gnuBufPutc(&all, '(');
        gnuBufPut(&all, tr, strlen(tr));
        gnuBufPutc(&all, ')');
        free(tr);
        free(b.s);
        free(prefix.s);
        return all.s;
    }
    if (split) {
        GnuBuf all = {NULL, 0, 0};
        gnuBufPut(&all, "", 0);
        gnuBufPutc(&all, '(');
        gnuBufPut(&all, prefix.s, prefix.n);
        gnuBufPut(&all, ")(", 2);
        gnuBufPut(&all, b.s, b.n);
        gnuBufPutc(&all, ')');
        *prefixGroup = 1;
        *bodyGroup = 2;
        free(b.s);
        free(prefix.s);
        return all.s;
    }
    free(prefix.s);
    return b.s;
unsupported:
    fprintf(stderr, "grep: unsupported Perl regular expression construct in %s\n", pat);
    free(b.s);
    free(prefix.s);
    return NULL;
}

/* GNU reads an unfinished interval ("a{1") as literal text; the host's
 * extended syntax rejects it. Escapes each '{' that does not start one. */
static char *grepLiteralBraces(const char *pat) {
    GnuBuf b = {NULL, 0, 0};
    gnuBufPut(&b, "", 0);
    for (const char *p = pat; *p; p++) {
        if (*p == '\\' && p[1]) { gnuBufPut(&b, p, 2); p++; continue; }
        if (*p == '[') { p = grepBracket(&b, p) - 1; continue; }
        if (*p == '{') {
            const char *q = p + 1;
            while (isdigit((unsigned char)*q)) q++;
            if (*q == ',') { q++; while (isdigit((unsigned char)*q)) q++; }
            if (*q != '}' || q == p + 1) { gnuBufPut(&b, "\\{", 2); continue; }
        }
        gnuBufPutc(&b, *p);
    }
    return b.s;
}

static bool grepCompile(Grep *g, const char *pat) {
    GrepPat *v = (GrepPat *)realloc(g->pats, (g->npats + 1) * sizeof(GrepPat));
    if (!v) return false;
    g->pats = v;
    GrepPat *gp = &g->pats[g->npats];
    memset(gp, 0, sizeof(*gp));
    if (!*pat) {
        gp->empty = true;
        g->npats++;
        return true;
    }
    bool icase = g->icase;
    char *src;
    int flags = 0;
    switch (g->mode) {
    case 'F': src = grepTranslateFixed(pat); break;
    case 'E': src = grepTranslateGnu(pat, true); flags = REG_EXTENDED; break;
    case 'P':
        src = grepTranslatePerl(pat, &icase, &gp->prefixGroup, &gp->bodyGroup);
        flags = REG_EXTENDED;
        if (!src) return false;
        break;
    default: src = grepTranslateGnu(pat, false); break;
    }
    if (!src) return false;
    if (icase) flags |= REG_ICASE;
    int r = regcomp(&gp->re, src, gnuRegexFlags(flags));
    if (r != 0 && (flags & REG_EXTENDED) && (r == REG_EBRACE || r == REG_BADBR)) {
        char *lit = grepLiteralBraces(src);
        if (lit) {
            r = regcomp(&gp->re, lit, gnuRegexFlags(flags));
            free(lit);
        }
    }
    free(src);
    if (r != 0) {
        fprintf(stderr, "grep: %s\n", gnuRegexMessage(r));
        return false;
    }
    g->npats++;
    return true;
}

/* --- Matching. --- */

static bool grepWordChar(Grep *g, unsigned char c) {
    return isalnum(c) || c == '_' || (g->utf8 && c >= 0x80);
}

/* The first match of one pattern in [start, len): the reported span. */
static bool grepExec(GrepPat *p, const char *line, size_t len, size_t start, size_t end, int eflags,
                     size_t *so, size_t *eo) {
    if (p->empty) {
        *so = *eo = start;
        return true;
    }
    regmatch_t m[10];
    m[0].rm_so = (regoff_t)start;
    m[0].rm_eo = (regoff_t)end;
    (void)len;
    if (regexec(&p->re, line, 10, m, eflags | REG_STARTEND | (start > 0 ? REG_NOTBOL : 0)) != 0) return false;
    int grp = p->bodyGroup;
    if (grp && m[grp].rm_so >= 0) {
        *so = (size_t)m[grp].rm_so;
        *eo = (size_t)m[grp].rm_eo;
    } else {
        *so = (size_t)m[0].rm_so;
        *eo = (size_t)m[0].rm_eo;
    }
    return true;
}

/* GNU's -w: a match must not touch word characters; failing that, try a
 * shorter match at the same place, then further on. -x: the whole line. */
static bool grepPatMatch(Grep *g, GrepPat *p, const char *line, size_t len, size_t start, size_t *so, size_t *eo) {
    size_t s, e;
    if (!grepExec(p, line, len, start, len, 0, &s, &e)) return false;
    if (g->line) {
        /* Leftmost-longest: a whole-line match, if any, is found from 0. */
        if (start == 0 && s == 0 && e == len) { *so = s; *eo = e; return true; }
        return false;
    }
    if (!g->word) { *so = s; *eo = e; return true; }
    for (;;) {
        bool before = s > 0 && grepWordChar(g, (unsigned char)line[s - 1]);
        bool after = e < len && grepWordChar(g, (unsigned char)line[e]);
        if (!before && !after) { *so = s; *eo = e; return true; }
        size_t shorter = 0;
        if (e > s) {
            size_t ss, se;
            if (grepExec(p, line, len, s, e - 1, REG_NOTEOL, &ss, &se) && ss == s && se > s) shorter = se;
        }
        if (shorter) {
            e = shorter;
            continue;
        }
        if (s + 1 > len) return false;
        if (!grepExec(p, line, len, s + 1, len, 0, &s, &e)) return false;
    }
}

/* The leftmost (then longest) match of any pattern from start. */
static bool grepFind(Grep *g, const char *line, size_t len, size_t start, size_t *so, size_t *eo) {
    bool found = false;
    for (size_t i = 0; i < g->npats; i++) {
        size_t s, e;
        if (!grepPatMatch(g, &g->pats[i], line, len, start, &s, &e)) continue;
        if (!found || s < *so || (s == *so && e > *eo)) {
            *so = s;
            *eo = e;
            found = true;
        }
    }
    return found;
}

static bool grepSelected(Grep *g, const char *line, size_t len) {
    size_t so, eo;
    bool m = g->npats > 0 && grepFind(g, line, len, 0, &so, &eo);
    return m != g->invert;
}

/* --- Output. --- */

typedef struct {
    const char *name;     /* as printed */
    bool binaryNow;       /* a NUL seen: no more lines are printed */
    bool binaryMatched;   /* a selected line came after that */
    bool encodingError;
    intmax_t lastPrinted;  /* the last line printed from this file, 0 for none */
} GrepFile;

static bool grepUtf8Valid(const unsigned char *s, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned char c = s[i];
        size_t k;
        unsigned char lo = 0x80, hi = 0xbf;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xc2 && c <= 0xdf) k = 1;
        else if (c >= 0xe0 && c <= 0xef) { k = 2; if (c == 0xe0) lo = 0xa0; if (c == 0xed) hi = 0x9f; }
        else if (c >= 0xf0 && c <= 0xf4) { k = 3; if (c == 0xf0) lo = 0x90; if (c == 0xf4) hi = 0x8f; }
        else return false;
        if (i + k >= n) return false;
        if (s[i + 1] < lo || s[i + 1] > hi) return false;
        for (size_t j = 2; j <= k; j++)
            if ((s[i + j] & 0xc0) != 0x80) return false;
        i += k + 1;
    }
    return true;
}

static void grepNumber(Grep *g, intmax_t v, const char *color) {
    grepSgrStart(g, color);
    if (g->tab) printf("%*jd", g->numberWidth, v);
    else printf("%jd", v);
    grepSgrEnd(g, color);
}

static void grepSep(Grep *g, char sep) {
    grepSgrStart(g, g->cSep);
    putchar(sep);
    grepSgrEnd(g, g->cSep);
}

static void grepHead(Grep *g, GrepFile *f, intmax_t lineno, intmax_t offset, char sep) {
    bool any = false;
    if (g->withName == 1) {
        grepSgrStart(g, g->cFile);
        fputs(f->name, stdout);
        grepSgrEnd(g, g->cFile);
        if (g->nullName) putchar('\0');
        else grepSep(g, sep);
        any = true;
    }
    if (g->lineNumber) {
        grepNumber(g, lineno, g->cLine);
        grepSep(g, sep);
        any = true;
    }
    if (g->byteOffset) {
        grepNumber(g, offset, g->cByte);
        grepSep(g, sep);
        any = true;
    }
    if (g->tab && any) putchar('\t');
}

/* Prints a line, selected (':') or context ('-'). False when the file has
 * turned out to be binary and printing stops. */
static bool grepPrintLine(Grep *g, GrepFile *f, const char *line, size_t len, intmax_t lineno, intmax_t offset,
                          bool selected) {
    if (f->binaryNow) return false;
    if (g->binary != 't' && g->utf8 && !grepUtf8Valid((const unsigned char *)line, len)) {
        f->encodingError = true;
        f->binaryNow = true;
        return false;
    }
    /* "--" between groups that are not adjacent, in this file or across. */
    if (g->everOutput && g->groupSep && (g->before || g->after) &&
        (f->lastPrinted == 0 || lineno > f->lastPrinted + 1)) {
        grepSgrStart(g, g->cSep);
        fputs(g->groupSep, stdout);
        grepSgrEnd(g, g->cSep);
        putchar('\n');
    }
    g->everOutput = true;
    f->lastPrinted = lineno;
    char sep = selected ? ':' : '-';
    bool matching = selected != g->invert;
    const char *mcolor = selected ? g->cMatchSel : g->cMatchCx;
    if (g->only) {
        size_t start = 0, so, eo;
        while (start <= len && grepFind(g, line, len, start, &so, &eo)) {
            if (eo == so) {
                start = so + 1;
                continue;
            }
            grepHead(g, f, lineno, offset + (intmax_t)so, sep);
            grepSgrStart(g, mcolor);
            fwrite(line + so, 1, eo - so, stdout);
            grepSgrEnd(g, mcolor);
            putchar(g->eol);
            start = eo;
        }
        if (g->lineBuffered) fflush(stdout);
        return true;
    }
    grepHead(g, f, lineno, offset, sep);
    const char *lcolor = selected ? g->cSel : g->cCx;
    if (g->color && matching && mcolor && *mcolor && g->npats) {
        size_t pos = 0, start = 0, so, eo;
        while (start <= len && grepFind(g, line, len, start, &so, &eo)) {
            if (eo == so) {
                start = so + 1;
                continue;
            }
            grepSgrStart(g, lcolor);
            fwrite(line + pos, 1, so - pos, stdout);
            grepSgrEnd(g, lcolor);
            grepSgrStart(g, mcolor);
            fwrite(line + so, 1, eo - so, stdout);
            grepSgrEnd(g, mcolor);
            pos = start = eo;
        }
        grepSgrStart(g, lcolor);
        fwrite(line + pos, 1, len - pos, stdout);
        grepSgrEnd(g, lcolor);
    } else {
        grepSgrStart(g, lcolor);
        fwrite(line, 1, len, stdout);
        grepSgrEnd(g, lcolor);
    }
    putchar(g->eol);
    if (g->lineBuffered) fflush(stdout);
    return true;
}

/* --- Reading a file. --- */

static void grepWarn(Grep *g, const char *name, int err) {
    g->error = true;
    if (!g->noMessages) fprintf(stderr, "grep: %s: %s\n", grepName(name), strerror(err));
}

/* Searches one open descriptor; true when a line was selected. */
static bool grepFd(Grep *g, int fd, const char *name) {
    GrepFile f;
    memset(&f, 0, sizeof(f));
    f.name = grepName(name);
    struct stat st;
    g->numberWidth = 19;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        g->numberWidth = 1;
        for (intmax_t v = st.st_size; v >= 10; v /= 10) g->numberWidth++;
    }
    bool output = !(g->count || g->listWith || g->listWithout || g->quiet);
    size_t cap = 98304, len = 0, pos = 0;
    char *buf = (char *)malloc(cap + 1);
    GrepHeld *held = g->before > 0 ? (GrepHeld *)calloc((size_t)g->before, sizeof(GrepHeld)) : NULL;
    size_t nheld = 0, heldStart = 0;
    if (!buf || (g->before > 0 && !held)) {
        free(buf);
        free(held);
        return false;
    }
    intmax_t lineno = 0, offset = 0, selectedCount = 0, afterLeft = 0;
    bool eof = false, stop = false, binary = false, anySelected = false;
    intmax_t selectedAfterNul = 0;
    while (!stop) {
        /* Find the next line, reading more as needed. */
        char *nl = memchr(buf + pos, g->eol, len - pos);
        if (!nl && !eof) {
            if (pos > 0) {
                memmove(buf, buf + pos, len - pos);
                len -= pos;
                pos = 0;
            }
            if (len == cap) {
                char *nb = (char *)realloc(buf, cap * 2 + 1);
                if (!nb) break;
                buf = nb;
                cap *= 2;
            }
            ssize_t n;
            do {
                n = read(fd, buf + len, cap - len);
            } while (n < 0 && errno == EINTR);
            if (n < 0) {
                grepWarn(g, name, errno);
                break;
            }
            if (n == 0) {
                eof = true;
            } else {
                if (!binary && g->binary != 't' && g->eol == '\n' && memchr(buf + len, '\0', (size_t)n)) {
                    binary = true;
                    if (g->binary == 'w') break;   /* -I: not a match, stop reading */
                    f.binaryNow = true;
                }
                len += (size_t)n;
            }
            continue;
        }
        if (!nl && pos == len) break;
        size_t lineLen = nl ? (size_t)(nl - (buf + pos)) : len - pos;
        char *line = buf + pos;
        char saved = line[lineLen];
        line[lineLen] = '\0';
        lineno++;
        bool sel = (g->maxCount < 0 || selectedCount < g->maxCount) && grepSelected(g, line, lineLen);
        if (sel) {
            selectedCount++;
            anySelected = true;
            if (f.binaryNow) selectedAfterNul++;
            if (g->quiet) {
                g->anyMatch = true;
                g->done = true;
                line[lineLen] = saved;
                break;
            }
            if (g->listWith || g->listWithout) {
                line[lineLen] = saved;
                break;
            }
            if (output && !f.binaryNow) {
                for (size_t k = 0; k < nheld; k++) {
                    GrepHeld *h = &held[(heldStart + k) % (size_t)g->before];
                    grepPrintLine(g, &f, h->text, h->len, h->lineno, h->offset, false);
                }
                nheld = 0;
                heldStart = 0;
                if (!grepPrintLine(g, &f, line, lineLen, lineno, offset, true) && f.encodingError)
                    selectedAfterNul++;
                afterLeft = g->after;
            }
            if (g->maxCount >= 0 && selectedCount >= g->maxCount && afterLeft == 0) stop = true;
        } else if (output && !f.binaryNow) {
            if (afterLeft > 0) {
                grepPrintLine(g, &f, line, lineLen, lineno, offset, false);
                afterLeft--;
                if (g->maxCount >= 0 && selectedCount >= g->maxCount && afterLeft == 0) stop = true;
            } else if (g->before > 0) {
                GrepHeld *h;
                if (nheld == (size_t)g->before) {
                    h = &held[heldStart];
                    heldStart = (heldStart + 1) % (size_t)g->before;
                    nheld--;
                } else {
                    h = &held[(heldStart + nheld) % (size_t)g->before];
                }
                char *t = (char *)realloc(h->text, lineLen + 1);
                if (t) {
                    memcpy(t, line, lineLen);
                    h->text = t;
                    h->len = lineLen;
                    h->lineno = lineno;
                    h->offset = offset;
                    nheld++;
                }
            } else if (g->maxCount >= 0 && selectedCount >= g->maxCount) {
                stop = true;
            }
        } else if (g->maxCount >= 0 && selectedCount >= g->maxCount) {
            stop = true;
        }
        line[lineLen] = saved;
        offset += (intmax_t)lineLen + (nl ? 1 : 0);
        pos += lineLen + (nl ? 1 : 0);
        if (!nl) break;
    }
    if (held) {
        for (intmax_t k = 0; k < g->before; k++) free(held[k].text);
        free(held);
    }
    free(buf);
    if (binary && g->binary == 'w') anySelected = false;
    if (g->count) {
        if (g->withName == 1) {
            grepSgrStart(g, g->cFile);
            fputs(f.name, stdout);
            grepSgrEnd(g, g->cFile);
            if (g->nullName) putchar('\0');
            else grepSep(g, ':');
        }
        printf("%jd\n", g->binary == 'w' && binary ? (intmax_t)0 : selectedCount);
    }
    if ((g->listWith && anySelected) || (g->listWithout && !anySelected)) {
        grepSgrStart(g, g->cFile);
        fputs(f.name, stdout);
        grepSgrEnd(g, g->cFile);
        putchar(g->nullName ? '\0' : '\n');
    }
    if (output && f.binaryNow && selectedAfterNul > 0 && g->binary == 'b') {
        fflush(stdout);
        fprintf(stderr, "grep: %s: binary file matches\n", f.name);
    }
    if (anySelected) g->anyMatch = true;
    return anySelected;
}

/* --- Files and directories. --- */

static bool grepGlobAny(const GrepList *l, const char *name) {
    for (size_t i = 0; i < l->n; i++)
        if (fnmatch(l->v[i], name, 0) == 0) return true;
    return false;
}

/* GNU matches a command-line name by any suffix that follows a '/'. */
static bool grepGlobSuffix(const GrepList *l, const char *path) {
    if (grepGlobAny(l, path)) return true;
    for (const char *p = path; (p = strchr(p, '/')); ) {
        p++;
        if (*p && *p != '/' && grepGlobAny(l, p)) return true;
    }
    return false;
}

static bool grepFileWanted(Grep *g, const char *name, bool commandLine) {
    if (commandLine) {
        if (g->exclude.n && grepGlobSuffix(&g->exclude, name)) return false;
        if (g->include.n && !grepGlobSuffix(&g->include, name)) return false;
        return true;
    }
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    if (g->exclude.n && grepGlobAny(&g->exclude, base)) return false;
    if (g->include.n && !grepGlobAny(&g->include, base)) return false;
    return true;
}

static void grepPath(Grep *g, const char *path, const char *shown, bool commandLine);

static void grepDir(Grep *g, const char *path, const char *shown) {
    DIR *d = opendir(path);
    if (!d) {
        grepWarn(g, shown, errno);
        return;
    }
    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            char **v = (char **)realloc(names, cap * sizeof(char *));
            if (!v) break;
            names = v;
        }
        names[n++] = strdup(de->d_name);
    }
    closedir(d);
    for (size_t i = 0; i < n && !g->done; i++) {
        size_t pl = strlen(path), sl = strlen(shown), nl = strlen(names[i]);
        char *cp = (char *)malloc(pl + nl + 2), *cs = (char *)malloc(sl + nl + 2);
        if (cp && cs) {
            snprintf(cp, pl + nl + 2, "%s%s%s", path, pl && path[pl - 1] != '/' ? "/" : "", names[i]);
            if (sl == 0) snprintf(cs, nl + 1, "%s", names[i]);
            else snprintf(cs, sl + nl + 2, "%s%s%s", shown, shown[sl - 1] != '/' ? "/" : "", names[i]);
            grepPath(g, cp, cs, false);
        }
        free(cp);
        free(cs);
        free(names[i]);
    }
    for (size_t i = 0; i < n; i++) if (g->done) free(names[i]);
    free(names);
}

static void grepPath(Grep *g, const char *path, const char *shown, bool commandLine) {
    if (!strcmp(path, "-") && commandLine) {
        grepFd(g, 0, g->label ? g->label : "-");
        return;
    }
    struct stat st;
    bool follow = commandLine || g->deref;
    if ((follow ? stat(path, &st) : lstat(path, &st)) != 0) {
        if (!follow || lstat(path, &st) != 0 || commandLine) {
            grepWarn(g, shown, errno);
            return;
        }
    }
    if (S_ISLNK(st.st_mode)) return;   /* -r: links met while recursing are skipped */
    if (S_ISDIR(st.st_mode)) {
        if (g->directories == 'R') {
            const char *base = strrchr(shown, '/');
            base = base && base[1] ? base + 1 : shown;
            if (!commandLine && g->excludeDir.n && grepGlobAny(&g->excludeDir, base)) return;
            if (commandLine && g->excludeDir.n && *shown && grepGlobSuffix(&g->excludeDir, shown)) return;
            grepDir(g, path, shown);
            return;
        }
        if (g->directories == 's') return;
        g->error = true;
        if (!g->noMessages) fprintf(stderr, "grep: %s: Is a directory\n", shown);
        return;
    }
    if (!grepFileWanted(g, shown, commandLine)) return;
    if (!S_ISREG(st.st_mode) && (g->devices == 's' || (!commandLine && g->directories == 'R'))) return;
    FILE *fp = smallclueAppOpenRead(path);
    if (!fp) {
        grepWarn(g, shown, errno);
        return;
    }
    grepFd(g, fileno(fp), shown);
    fclose(fp);
}

/* --- Options. --- */

static int grepUsageError(void) {
    fputs("Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", stderr);
    return 2;
}

static void grepHelp(void) {
    fputs("Usage: grep [OPTION]... PATTERNS [FILE]...\n"
          "Search for PATTERNS in each FILE.\n"
          "Example: grep -i 'hello world' menu.h main.c\n"
          "PATTERNS can contain multiple patterns separated by newlines.\n"
          "\n"
          "Pattern selection and interpretation:\n"
          "  -E, --extended-regexp     PATTERNS are extended regular expressions\n"
          "  -F, --fixed-strings       PATTERNS are strings\n"
          "  -G, --basic-regexp        PATTERNS are basic regular expressions\n"
          "  -P, --perl-regexp         PATTERNS are Perl regular expressions (a subset)\n"
          "  -e, --regexp=PATTERNS     use PATTERNS for matching\n"
          "  -f, --file=FILE           take PATTERNS from FILE\n"
          "  -i, --ignore-case         ignore case distinctions in patterns and data\n"
          "      --no-ignore-case      do not ignore case distinctions (default)\n"
          "  -w, --word-regexp         match only whole words\n"
          "  -x, --line-regexp         match only whole lines\n"
          "  -z, --null-data           a data line ends in 0 byte, not newline\n"
          "\n"
          "Miscellaneous:\n"
          "  -s, --no-messages         suppress error messages\n"
          "  -v, --invert-match        select non-matching lines\n"
          "  -V, --version             display version information and exit\n"
          "      --help                display this help text and exit\n"
          "\n"
          "Output control:\n"
          "  -m, --max-count=NUM       stop after NUM selected lines\n"
          "  -b, --byte-offset         print the byte offset with output lines\n"
          "  -n, --line-number         print line number with output lines\n"
          "      --line-buffered       flush output on every line\n"
          "  -H, --with-filename       print file name with output lines\n"
          "  -h, --no-filename         suppress the file name prefix on output\n"
          "      --label=LABEL         use LABEL as the standard input file name prefix\n"
          "  -o, --only-matching       show only nonempty parts of lines that match\n"
          "  -q, --quiet, --silent     suppress all normal output\n"
          "      --binary-files=TYPE   assume that binary files are TYPE;\n"
          "                            TYPE is 'binary', 'text', or 'without-match'\n"
          "  -a, --text                equivalent to --binary-files=text\n"
          "  -I                        equivalent to --binary-files=without-match\n"
          "  -d, --directories=ACTION  how to handle directories;\n"
          "                            ACTION is 'read', 'recurse', or 'skip'\n"
          "  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;\n"
          "                            ACTION is 'read' or 'skip'\n"
          "  -r, --recursive           like --directories=recurse\n"
          "  -R, --dereference-recursive  likewise, but follow all symlinks\n"
          "      --include=GLOB        search only files that match GLOB (a file pattern)\n"
          "      --exclude=GLOB        skip files that match GLOB\n"
          "      --exclude-from=FILE   skip files that match any file pattern from FILE\n"
          "      --exclude-dir=GLOB    skip directories that match GLOB\n"
          "  -L, --files-without-match  print only names of FILEs with no selected lines\n"
          "  -l, --files-with-matches  print only names of FILEs with selected lines\n"
          "  -c, --count               print only a count of selected lines per FILE\n"
          "  -T, --initial-tab         make tabs line up (if needed)\n"
          "  -Z, --null                print 0 byte after FILE name\n"
          "\n"
          "Context control:\n"
          "  -B, --before-context=NUM  print NUM lines of leading context\n"
          "  -A, --after-context=NUM   print NUM lines of trailing context\n"
          "  -C, --context=NUM         print NUM lines of output context\n"
          "  -NUM                      same as --context=NUM\n"
          "      --group-separator=SEP  print SEP on line between matches with context\n"
          "      --no-group-separator  do not print separator for matches with context\n"
          "      --color[=WHEN],\n"
          "      --colour[=WHEN]       use markers to highlight the matching strings;\n"
          "                            WHEN is 'always', 'never', or 'auto'\n"
          "  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)\n"
          "\n"
          "When FILE is '-', read standard input.  With no FILE, read '.' if\n"
          "recursive, '-' otherwise.  With fewer than two FILEs, assume -h.\n"
          "Exit status is 0 if any line is selected, 1 otherwise;\n"
          "if any error occurs and -q is not given, the exit status is 2.\n",
          stdout);
}

typedef struct {
    const char *name;
    char shortEq;
    int arg;       /* 0 none, 1 required, 2 optional */
} GrepLong;

static const GrepLong grepLongs[] = {
    {"after-context", 'A', 1}, {"basic-regexp", 'G', 0}, {"before-context", 'B', 1},
    {"binary", 'U', 0}, {"binary-files", 1, 1}, {"byte-offset", 'b', 0}, {"color", 2, 2},
    {"colour", 2, 2}, {"context", 'C', 1}, {"count", 'c', 0}, {"dereference-recursive", 'R', 0},
    {"devices", 'D', 1}, {"directories", 'd', 1}, {"exclude", 3, 1}, {"exclude-dir", 4, 1},
    {"exclude-from", 5, 1}, {"extended-regexp", 'E', 0}, {"file", 'f', 1},
    {"files-with-matches", 'l', 0}, {"files-without-match", 'L', 0}, {"fixed-strings", 'F', 0},
    {"group-separator", 6, 1}, {"help", 7, 0}, {"ignore-case", 'i', 0}, {"include", 8, 1},
    {"initial-tab", 'T', 0}, {"invert-match", 'v', 0}, {"label", 9, 1}, {"line-buffered", 10, 0},
    {"line-number", 'n', 0}, {"line-regexp", 'x', 0}, {"max-count", 'm', 1},
    {"no-filename", 'h', 0}, {"no-group-separator", 11, 0}, {"no-ignore-case", 12, 0},
    {"no-messages", 's', 0}, {"null", 'Z', 0}, {"null-data", 'z', 0}, {"only-matching", 'o', 0},
    {"perl-regexp", 'P', 0}, {"quiet", 'q', 0}, {"recursive", 'r', 0}, {"regexp", 'e', 1},
    {"silent", 'q', 0}, {"text", 'a', 0}, {"version", 'V', 0}, {"with-filename", 'H', 0},
    {"word-regexp", 'w', 0},
};

typedef struct {
    char **pats;
    size_t npats;
    bool havePats;
} GrepPatterns;

static bool grepAddPatterns(GrepPatterns *p, const char *text, size_t len) {
    /* Each newline-separated piece is its own pattern. */
    size_t start = 0;
    p->havePats = true;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || text[i] == '\n') {
            char **v = (char **)realloc(p->pats, (p->npats + 1) * sizeof(char *));
            if (!v) return false;
            p->pats = v;
            p->pats[p->npats++] = strndup(text + start, i - start);
            start = i + 1;
        }
    }
    return true;
}

static bool grepReadAll(const char *name, char **out, size_t *len) {
    int fd = 0;
    FILE *fp = NULL;
    if (strcmp(name, "-")) {
        fp = smallclueAppOpenRead(name);
        if (!fp) return false;
        fd = fileno(fp);
    }
    size_t cap = 4096, n = 0;
    char *b = (char *)malloc(cap);
    for (;;) {
        if (!b) break;
        if (n == cap) {
            char *nb = (char *)realloc(b, cap *= 2);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
        }
        ssize_t r = read(fd, b + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    if (fp) fclose(fp);
    *out = b;
    *len = n;
    return b != NULL;
}

static bool grepListAdd(GrepList *l, const char *s) {
    char **v = (char **)realloc(l->v, (l->n + 1) * sizeof(char *));
    if (!v) return false;
    l->v = v;
    l->v[l->n++] = (char *)s;
    return true;
}

static bool grepContext(const char *val, intmax_t *out) {
    char *end;
    errno = 0;
    intmax_t v = strtoimax(val, &end, 10);
    if (!*val || *end || v < 0 || errno) {
        fprintf(stderr, "grep: %s: invalid context length argument\n", val);
        return false;
    }
    *out = v;
    return true;
}

typedef struct {
    GrepPatterns pp;
    char **excludeFromBufs;
    size_t nExcludeFrom;
    int status;
    int colorWhen;        /* -1 never (GNU's default), 0 auto, 1 always */
    intmax_t contextAll;
} GrepParse;

/* One option; 1 when grep must stop now with ps->status. */
static int grepApply(Grep *g, GrepParse *ps, int c, const char *val) {
    switch (c) {
    case 'E': case 'F': case 'G': case 'P': g->mode = (char)c; break;
    case 'e': if (!grepAddPatterns(&ps->pp, val, strlen(val))) return 1; break;
    case 'f': {
        char *text;
        size_t len;
        if (!grepReadAll(val, &text, &len)) {
            fprintf(stderr, "grep: %s: %s\n", val, strerror(errno));
            return 1;
        }
        ps->pp.havePats = true;
        if (len > 0) {
            if (text[len - 1] == '\n') len--;
            grepAddPatterns(&ps->pp, text, len);
        }
        free(text);
        break;
    }
    case 'i': case 'y': g->icase = true; break;
    case 12: g->icase = false; break;
    case 'w': g->word = true; break;
    case 'x': g->line = true; break;
    case 'z': g->eol = '\0'; break;
    case 's': g->noMessages = true; break;
    case 'v': g->invert = true; break;
    case 'V': puts("grep (SmallCLUE) 3.11"); ps->status = 0; return 1;
    case 7: grepHelp(); ps->status = 0; return 1;
    case 'm': {
        char *end;
        errno = 0;
        intmax_t v = strtoimax(val, &end, 10);
        if (!*val || *end || errno) {
            fputs("grep: invalid max count\n", stderr);
            return 1;
        }
        g->maxCount = v < 0 ? -1 : v;
        break;
    }
    case 'b': g->byteOffset = true; break;
    case 'n': g->lineNumber = true; break;
    case 10: g->lineBuffered = true; break;
    case 'H': g->withName = 1; break;
    case 'h': g->withName = 0; break;
    case 9: g->label = val; break;
    case 'o': g->only = true; break;
    case 'q': g->quiet = true; break;
    case 1:
        if (!strcmp(val, "binary")) g->binary = 'b';
        else if (!strcmp(val, "text")) g->binary = 't';
        else if (!strcmp(val, "without-match")) g->binary = 'w';
        else {
            fputs("grep: unknown binary-files type\n", stderr);
            return 1;
        }
        break;
    case 'a': g->binary = 't'; break;
    case 'I': g->binary = 'w'; break;
    case 'd':
        if (!strcmp(val, "read")) g->directories = 'r';
        else if (!strcmp(val, "skip")) g->directories = 's';
        else if (!strcmp(val, "recurse")) { g->directories = 'R'; g->recursive = true; }
        else {
            char q[256];
            fprintf(stderr, "grep: invalid argument %s for '--directories'\n"
                            "Valid arguments are:\n  - 'read'\n  - 'recurse'\n  - 'skip'\n",
                    gnuQuoteLocale(val, q, sizeof(q)));
            ps->status = grepUsageError();
            return 1;
        }
        break;
    case 'D':
        if (!strcmp(val, "read")) g->devices = 'r';
        else if (!strcmp(val, "skip")) g->devices = 's';
        else {
            fputs("grep: unknown devices method\n", stderr);
            return 1;
        }
        break;
    case 'r': g->recursive = true; g->directories = 'R'; break;
    case 'R': g->recursive = true; g->deref = true; g->directories = 'R'; break;
    case 3: grepListAdd(&g->exclude, val); break;
    case 4: grepListAdd(&g->excludeDir, val); break;
    case 8: grepListAdd(&g->include, val); break;
    case 5: {
        char *text;
        size_t len;
        if (!grepReadAll(val, &text, &len)) {
            fprintf(stderr, "grep: %s: %s\n", val, strerror(errno));
            return 1;
        }
        char **nb = (char **)realloc(ps->excludeFromBufs, (ps->nExcludeFrom + 1) * sizeof(char *));
        if (!nb) { free(text); return 1; }
        ps->excludeFromBufs = nb;
        char *z = (char *)realloc(text, len + 1);
        if (!z) { free(text); return 1; }
        z[len] = '\0';
        ps->excludeFromBufs[ps->nExcludeFrom++] = z;
        char *save = NULL;
        for (char *t = strtok_r(z, "\n", &save); t; t = strtok_r(NULL, "\n", &save)) grepListAdd(&g->exclude, t);
        break;
    }
    case 'L': g->listWithout = true; g->listWith = false; break;
    case 'l': g->listWith = true; g->listWithout = false; break;
    case 'c': g->count = true; break;
    case 'T': g->tab = true; break;
    case 'Z': g->nullName = true; break;
    case 'A': if (!grepContext(val, &g->after)) return 1; break;
    case 'B': if (!grepContext(val, &g->before)) return 1; break;
    case 'C': if (!grepContext(val, &ps->contextAll)) return 1; break;
    case 6: g->groupSep = val; break;
    case 11: g->groupSep = NULL; break;
    case 2:
        if (!val) ps->colorWhen = 0;
        else if (!strcmp(val, "always") || !strcmp(val, "yes") || !strcmp(val, "force")) ps->colorWhen = 1;
        else if (!strcmp(val, "never") || !strcmp(val, "no") || !strcmp(val, "none")) ps->colorWhen = -1;
        else if (!strcmp(val, "auto") || !strcmp(val, "tty") || !strcmp(val, "if-tty")) ps->colorWhen = 0;
        else {
            grepHelp();   /* as GNU does, on standard output */
            ps->status = 2;
            return 1;
        }
        break;
    case 'U': break;
    default: break;
    }
    return 0;
}

int smallclueGrepCommand(int argc, char **argv) {
    Grep *g = (Grep *)calloc(1, sizeof(Grep));
    GrepParse ps = {{NULL, 0, false}, NULL, 0, 2, -1, -1};
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    size_t nfiles = 0;
    int status = 2;
    if (!g || !files) { free(g); free(files); return 2; }
    g->mode = 'G';
    g->withName = -1;
    g->maxCount = -1;
    g->before = g->after = -1;
    g->groupSep = "--";
    g->binary = 'b';
    g->directories = 'r';
    g->devices = 'r';
    g->eol = '\n';
    g->utf8 = gnuUtf8Locale();

    bool endOfOptions = false;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            files[nfiles++] = arg;
            continue;
        }
        if (!strcmp(arg, "--")) { endOfOptions = true; continue; }
        int c;
        const char *val = NULL;
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            const GrepLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(grepLongs) / sizeof(grepLongs[0]); k++) {
                if (strncmp(grepLongs[k].name, opt, len)) continue;
                if (strlen(grepLongs[k].name) == len) { m = &grepLongs[k]; matches = 1; break; }
                if (m && m->shortEq == grepLongs[k].shortEq) continue;   /* --col: color/colour */
                m = &grepLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "grep: option '%s' is ambiguous\n" : "grep: unrecognized option '%s'\n", arg);
                status = grepUsageError();
                goto done;
            }
            if (eq) {
                if (m->arg == 0) {
                    fprintf(stderr, "grep: option '--%s' doesn't allow an argument\n", m->name);
                    status = grepUsageError();
                    goto done;
                }
                val = eq + 1;
            } else if (m->arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "grep: option '--%s' requires an argument\n", m->name);
                    status = grepUsageError();
                    goto done;
                }
                val = argv[++i];
            }
            if (grepApply(g, &ps, m->shortEq, val)) { status = ps.status; goto done; }
            continue;
        }
        if (isdigit((unsigned char)arg[1])) {
            /* -NUM: context, digits possibly mixed with other letters. */
            const char *p = arg + 1;
            intmax_t v = 0;
            while (isdigit((unsigned char)*p)) v = v * 10 + (*p++ - '0');
            ps.contextAll = v;
            if (!*p) continue;
            arg = (char *)p - 1;
        }
        for (const char *p = arg + 1; *p; p++) {
            c = *p;
            val = NULL;
            if (strchr("ABCDdefm", c)) {
                if (p[1]) val = p + 1;
                else if (i + 1 < argc) val = argv[++i];
                else {
                    fprintf(stderr, "grep: option requires an argument -- '%c'\n", c);
                    status = grepUsageError();
                    goto done;
                }
            } else if (!strchr("EFGPiywxzsvVbnHhoqaIrRLlcTZU", c)) {
                if (isdigit((unsigned char)c)) {
                    ps.contextAll = c - '0';
                    while (isdigit((unsigned char)p[1])) ps.contextAll = ps.contextAll * 10 + (*++p - '0');
                    continue;
                }
                fprintf(stderr, "grep: invalid option -- '%c'\n", c);
                status = grepUsageError();
                goto done;
            }
            if (grepApply(g, &ps, c, val)) { status = ps.status; goto done; }
            if (val) break;
        }
    }
    if (g->before < 0) g->before = ps.contextAll >= 0 ? ps.contextAll : 0;
    if (g->after < 0) g->after = ps.contextAll >= 0 ? ps.contextAll : 0;

    if (!ps.pp.havePats) {
        if (nfiles == 0) { status = grepUsageError(); goto done; }
        grepAddPatterns(&ps.pp, files[0], strlen(files[0]));
        memmove(files, files + 1, --nfiles * sizeof(char *));
    }
    for (size_t k = 0; k < ps.pp.npats; k++)
        if (!grepCompile(g, ps.pp.pats[k])) goto done;

    if (ps.colorWhen == 1) g->color = true;
    else if (ps.colorWhen == 0) {
        const char *term = getenv("TERM");
        g->color = isatty(1) && term && strcmp(term, "dumb");
    }
    if (g->color) grepParseColors(g);
    if (g->maxCount == 0) { status = 1; goto done; }

    bool recurseDot = false;
    if (nfiles == 0) {
        files[nfiles++] = g->recursive ? (char *)"." : (char *)"-";
        recurseDot = g->recursive;
    }
    if (g->withName < 0) g->withName = (nfiles > 1 || g->recursive) ? 1 : 0;
    for (size_t k = 0; k < nfiles && !g->done; k++) {
        if (recurseDot) grepDir(g, ".", "");
        else grepPath(g, files[k], files[k], true);
    }
    if (g->quiet && g->anyMatch) status = 0;
    else if (g->error) status = 2;
    else status = g->anyMatch ? 0 : 1;

done:
    fflush(stdout);
    for (size_t k = 0; k < g->npats; k++)
        if (!g->pats[k].empty) regfree(&g->pats[k].re);
    free(g->pats);
    for (size_t k = 0; k < ps.pp.npats; k++) free(ps.pp.pats[k]);
    free(ps.pp.pats);
    free(g->include.v);
    free(g->exclude.v);
    free(g->excludeDir.v);
    for (size_t k = 0; k < ps.nExcludeFrom; k++) free(ps.excludeFromBufs[k]);
    free(ps.excludeFromBufs);
    free(files);
    free(g);
    return status;
}
