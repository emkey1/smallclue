/*
 * tac: GNU coreutils 9 compatible. Records end with the separator (or,
 * with -b, begin with it), found by GNU's backward search -- each match
 * the one starting latest, within what is left -- so a regex (-r, in GNU
 * regex's default Emacs syntax: + and ? are operators, | ( ) { } literal,
 * \| \( \) the operators) splits "22" by [0-9]+ into two separators, as
 * GNU does. An empty separator is a NUL. Each FILE reversed on its own.
 */

#include "tac_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_regex.h"
#include "gnu_util.h"

#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *sep;
    size_t sepLen;
    bool before, isRegex;
    regex_t re;
} Tac;

/* GNU regex's Emacs syntax as an ERE. */
static char *tacEmacsToEre(const char *s) {
    size_t n = strlen(s);
    char *out = (char *)malloc(n * 2 + 1), *o = out;
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '\\' && i + 1 < n) {
            char d = s[++i];
            if (d == '(' || d == ')' || d == '|') *o++ = d;
            else if (d == '{' || d == '}') { *o++ = '\\'; *o++ = d; }
            else { *o++ = '\\'; *o++ = d; }
        } else if (c == '(' || c == ')' || c == '|' || c == '{' || c == '}') {
            *o++ = '\\';
            *o++ = c;
        } else if (c == '[') {
            /* a bracket expression passes through whole */
            size_t j = i + 1;
            if (j < n && s[j] == '^') j++;
            if (j < n && s[j] == ']') j++;
            while (j < n && s[j] != ']') {
                if (s[j] == '[' && j + 1 < n && (s[j + 1] == ':' || s[j + 1] == '.' || s[j + 1] == '=')) {
                    char close = s[j + 1];
                    j += 2;
                    while (j + 1 < n && !(s[j] == close && s[j + 1] == ']')) j++;
                    j += 2;
                } else {
                    j++;
                }
            }
            size_t len = (j < n ? j + 1 : n) - i;
            memcpy(o, s + i, len);
            o += len;
            i += len - 1;
        } else {
            *o++ = c;
        }
    }
    *o = '\0';
    return out;
}

/* The separator latest-starting within [0, limit); false if none. */
static bool tacFind(Tac *t, const char *buf, size_t limit, size_t *ms, size_t *me) {
    if (!t->isRegex) {
        if (limit < t->sepLen) return false;
        for (size_t p = limit - t->sepLen + 1; p-- > 0;)
            if (!memcmp(buf + p, t->sep, t->sepLen)) {
                *ms = p;
                *me = p + t->sepLen;
                return true;
            }
        return false;
    }
    /* each search gives the leftmost match from x; walking x forward lists
     * every start, and the last one wins */
    bool found = false;
    size_t x = 0;
    while (x < limit) {
        regmatch_t m[1];
        m[0].rm_so = (regoff_t)x;
        m[0].rm_eo = (regoff_t)limit;
        if (regexec(&t->re, buf, 1, m, REG_STARTEND | (x ? REG_NOTBOL : 0)) != 0) break;
        if (m[0].rm_eo > m[0].rm_so) {
            *ms = (size_t)m[0].rm_so;
            *me = (size_t)m[0].rm_eo;
            found = true;
        }
        x = (size_t)m[0].rm_so + 1;
    }
    return found;
}

static void tacOutput(Tac *t, const char *buf, size_t len) {
    size_t pastEnd = len, limit = len, ms, me;
    while (tacFind(t, buf, limit, &ms, &me)) {
        size_t from = t->before ? ms : me;
        fwrite(buf + from, 1, pastEnd - from, stdout);
        pastEnd = from;
        limit = ms;
    }
    fwrite(buf, 1, pastEnd, stdout);
}

static const GnuLongOpt tacLongs[] = {
    {"before", GNU_NO_ARG, 'b'}, {"regex", GNU_NO_ARG, 'r'}, {"separator", GNU_REQ_ARG, 's'},
    {"help", GNU_NO_ARG, 1},     {"version", GNU_NO_ARG, 2},
};

int smallclueTacCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "tac", "brs:", tacLongs, sizeof(tacLongs) / sizeof(tacLongs[0]));
    Tac t;
    memset(&t, 0, sizeof(t));
    t.sep = "\n";
    int c, status = 0;
    bool reOk = false;
    char q[4096];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'b': t.before = true; break;
        case 'r': t.isRegex = true; break;
        case 's': t.sep = g.arg; break;
        case 1:
            fputs("Usage: tac [OPTION]... [FILE]...\n"
                  "Write each FILE to standard output, last line first.\n\n"
                  "With no FILE, or when FILE is -, read standard input.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -b, --before             attach the separator before instead of after\n"
                  "  -r, --regex              interpret the separator as a regular expression\n"
                  "  -s, --separator=STRING   use STRING as the separator instead of newline\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            goto done;
        case 2: puts("tac (SmallCLUE) 9.4"); goto done;
        default:
            fputs("Try 'tac --help' for more information.\n", stderr);
            status = 1;
            goto done;
        }
    }
    t.sepLen = strlen(t.sep);
    if (t.sepLen == 0) t.sepLen = 1;   /* "": the NUL byte */
    if (t.isRegex) {
        char *ere = tacEmacsToEre(t.sep);
        int rc = ere ? regcomp(&t.re, ere, gnuRegexFlags(REG_EXTENDED)) : REG_ESPACE;
        free(ere);
        if (rc != 0) {
            fprintf(stderr, "tac: %s\n", gnuRegexMessage(rc));
            status = 1;
            goto done;
        }
        reOk = true;
    }
    for (int i = 0; i < (g.nops ? g.nops : 1); i++) {
        const char *name = g.nops ? g.ops[i] : "-";
        bool isStdin = !strcmp(name, "-");
        FILE *f = isStdin ? stdin : smallclueAppOpenRead(name);
        if (!f) {
            fprintf(stderr, "tac: failed to open %s for reading: %s\n", gnuQuote(name, q, sizeof(q)), strerror(errno));
            status = 1;
            continue;
        }
        char *buf = NULL;
        size_t len = 0, cap = 0, n;
        for (;;) {
            if (len + 65536 + 1 > cap) {
                cap = cap ? cap * 2 : 131072;
                char *p = (char *)realloc(buf, cap);
                if (!p) break;
                buf = p;
            }
            n = fread(buf + len, 1, cap - len - 1, f);
            if (n == 0) break;
            len += n;
        }
        if (ferror(f)) {
            fprintf(stderr, "tac: %s: read error: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            status = 1;
        } else if (buf) {
            buf[len] = '\0';
            tacOutput(&t, buf, len);
        }
        free(buf);
        if (isStdin) clearerr(stdin);
        else fclose(f);
    }
done:
    if (reOk) regfree(&t.re);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("tac", errno);
        status = 1;
    }
    return status;
}
