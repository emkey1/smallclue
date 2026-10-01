/*
 * nl: GNU coreutils 9 compatible. Styles a/t/n/pBRE for the header, body
 * and footer; -v start (any integer), -i increment, -l blank-line joining,
 * -n ln/rn/rz, -w, -s, -p, -d section delimiters (\:\:\: header, \:\: body,
 * \: footer, numbering reset at each unless -p), files numbered as one
 * stream, GNU's messages and its line-number overflow check.
 */

#include "nl_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_regex.h"
#include "gnu_util.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NL_HEADER, NL_BODY, NL_FOOTER };

typedef struct {
    char type;         /* a t n p */
    regex_t re;
    bool haveRe;
} NlStyle;

typedef struct {
    NlStyle style[3];
    int section;
    intmax_t start, incr, lineNo;
    intmax_t blankJoin, blanks;
    bool overflow, reset;
    int width;
    const char *fmt;
    const char *sep;
    char *delim;        /* the footer delimiter; body is 2x, header 3x */
    size_t delimLen;
    int status;
} Nl;

static int nlTry(void) {
    fputs("Try 'nl --help' for more information.\n", stderr);
    return 1;
}

/* xdectoimax: false after GNU's message (with glibc's errno text for a
 * value out of range). */
static bool nlNumber(const char *s, intmax_t min, intmax_t max, const char *what, intmax_t *out) {
    char *end, q[512];
    errno = 0;
    intmax_t v = strtoimax(s, &end, 10);
    const char *why = NULL;
    if (end == s || *end) {
        fprintf(stderr, "nl: %s: %s\n", what, gnuQuoteLocale(s, q, sizeof(q)));
        return false;
    }
    if (errno == ERANGE) why = "Value too large for defined data type";
    else if (v < min || v > max)
        why = v > INT_MAX / 2 || v < INT_MIN / 2 ? "Value too large for defined data type"
                                                 : "Numerical result out of range";
    if (why) {
        fprintf(stderr, "nl: %s: %s: %s\n", what, gnuQuoteLocale(s, q, sizeof(q)), why);
        return false;
    }
    *out = v;
    return true;
}

/* -b/-h/-f STYLE: 0, or after the message 1 (a bad style: "Try ...")
 * or 2 (a bad regex: the message alone). */
static int nlStyle(NlStyle *st, const char *arg, const char *which) {
    char q[512];
    if (st->haveRe) {
        regfree(&st->re);
        st->haveRe = false;
    }
    if ((arg[0] == 'a' || arg[0] == 't' || arg[0] == 'n') && !arg[1]) {
        st->type = arg[0];
        return 0;
    }
    if (arg[0] == 'p') {
        int rc = regcomp(&st->re, arg + 1, gnuRegexFlags(0));
        if (rc != 0) {
            /* glibc's regex calls a bracket opened at the very end ("[",
             * "a[^") invalid rather than unmatched */
            size_t n = strlen(arg + 1);
            const char *re = arg + 1;
            bool atEnd = rc == REG_EBRACK && n && (re[n - 1] == '[' || (n > 1 && re[n - 1] == '^' && re[n - 2] == '['));
            fprintf(stderr, "nl: %s\n", atEnd ? "Invalid regular expression" : gnuRegexMessage(rc));
            return 2;
        }
        st->haveRe = true;
        st->type = 'p';
        return 0;
    }
    fprintf(stderr, "nl: invalid %s numbering style: %s\n", which, gnuQuoteLocale(arg, q, sizeof(q)));
    return 1;
}

static bool nlNumbered(Nl *nl, const char *line, size_t len) {
    if (nl->overflow) {
        fputs("nl: line number overflow\n", stderr);
        return false;
    }
    printf(nl->fmt, nl->width, nl->lineNo);
    fputs(nl->sep, stdout);
    if (__builtin_add_overflow(nl->lineNo, nl->incr, &nl->lineNo)) nl->overflow = true;
    fwrite(line, 1, len, stdout);
    return true;
}

static void nlUnnumbered(const Nl *nl, const char *line, size_t len) {
    for (size_t k = (size_t)nl->width + strlen(nl->sep); k; k--) putchar(' ');
    fwrite(line, 1, len, stdout);
}

/* One line, its newline included; false on overflow. */
static bool nlLine(Nl *nl, char *line, size_t len) {
    size_t text = len - 1;
    size_t d = nl->delimLen;
    if (text >= 2 && d >= 2 && !memcmp(line, nl->delim, 2)) {
        int kind = -1;
        for (int k = 3; k >= 1 && kind < 0; k--) {
            if (text != d * (size_t)k) continue;
            bool match = true;
            for (int r = 0; r < k && match; r++) match = !memcmp(line + d * (size_t)r, nl->delim, d);
            if (match) kind = k == 3 ? NL_HEADER : k == 2 ? NL_BODY : NL_FOOTER;
        }
        if (kind >= 0) {
            nl->section = kind;
            if (nl->reset) nl->lineNo = nl->start;
            putchar('\n');
            return true;
        }
    }
    NlStyle *st = &nl->style[nl->section];
    switch (st->type) {
    case 'a':
        if (nl->blankJoin > 1) {
            if (text > 0 || ++nl->blanks == nl->blankJoin) {
                nl->blanks = 0;
                return nlNumbered(nl, line, len);
            }
            nlUnnumbered(nl, line, len);
            return true;
        }
        return nlNumbered(nl, line, len);
    case 't':
        if (text > 0) return nlNumbered(nl, line, len);
        nlUnnumbered(nl, line, len);
        return true;
    case 'p': {
        line[text] = '\0';
        bool hit = regexec(&st->re, line, 0, NULL, 0) == 0;
        line[text] = '\n';
        if (hit) return nlNumbered(nl, line, len);
        nlUnnumbered(nl, line, len);
        return true;
    }
    default:
        nlUnnumbered(nl, line, len);
        return true;
    }
}

static bool nlFile(Nl *nl, FILE *in) {
    char *line = NULL;
    size_t cap = 0, len = 0;
    int c;
    bool ok = true;
    do {
        c = getc(in);
        if (c != EOF) {
            if (len + 2 > cap) {
                cap = cap ? cap * 2 : 256;
                char *p = (char *)realloc(line, cap);
                if (!p) break;
                line = p;
            }
            line[len++] = (char)c;
        }
        if ((c == '\n' || (c == EOF && len)) && ok) {
            if (c == EOF) line[len++] = '\n';
            ok = nlLine(nl, line, len);
            len = 0;
        }
    } while (c != EOF && ok);
    free(line);
    return ok;
}

static const GnuLongOpt nlLongs[] = {
    {"header-numbering", GNU_REQ_ARG, 'h'}, {"body-numbering", GNU_REQ_ARG, 'b'},
    {"footer-numbering", GNU_REQ_ARG, 'f'}, {"starting-line-number", GNU_REQ_ARG, 'v'},
    {"line-increment", GNU_REQ_ARG, 'i'},   {"no-renumber", GNU_NO_ARG, 'p'},
    {"join-blank-lines", GNU_REQ_ARG, 'l'}, {"number-separator", GNU_REQ_ARG, 's'},
    {"number-width", GNU_REQ_ARG, 'w'},     {"number-format", GNU_REQ_ARG, 'n'},
    {"section-delimiter", GNU_REQ_ARG, 'd'}, {"help", GNU_NO_ARG, 1},
    {"version", GNU_NO_ARG, 2},
};

int smallclueNlCommand(int argc, char **argv) {
    Nl nl;
    memset(&nl, 0, sizeof(nl));
    nl.style[NL_HEADER].type = 'n';
    nl.style[NL_BODY].type = 't';
    nl.style[NL_FOOTER].type = 'n';
    nl.section = NL_BODY;
    nl.start = 1;
    nl.incr = 1;
    nl.blankJoin = 1;
    nl.reset = true;
    nl.width = 6;
    nl.fmt = "%*jd";
    nl.sep = "\t";
    const char *delimArg = "\\:";
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "nl", "h:b:f:v:i:pl:s:w:n:d:", nlLongs, sizeof(nlLongs) / sizeof(nlLongs[0]));
    int c, status = 1;
    intmax_t v;
    char q[512];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'h': case 'b': case 'f': {
            int k = c == 'h' ? NL_HEADER : c == 'b' ? NL_BODY : NL_FOOTER;
            int bad = nlStyle(&nl.style[k], g.arg, c == 'h' ? "header" : c == 'b' ? "body" : "footer");
            if (bad == 1) goto try;
            if (bad) goto done;
            break;
        }
        case 'v':
            if (!nlNumber(g.arg, INTMAX_MIN, INTMAX_MAX, "invalid starting line number", &nl.start)) goto done;
            break;
        case 'i':
            if (!nlNumber(g.arg, INTMAX_MIN, INTMAX_MAX, "invalid line number increment", &nl.incr)) goto done;
            break;
        case 'p': nl.reset = false; break;
        case 'l':
            if (!nlNumber(g.arg, 0, INTMAX_MAX, "invalid line number of blank lines", &nl.blankJoin)) goto done;
            break;
        case 's': nl.sep = g.arg; break;
        case 'w':
            if (!nlNumber(g.arg, 1, INT_MAX, "invalid line number field width", &v)) goto done;
            nl.width = (int)v;
            break;
        case 'n':
            if (!strcmp(g.arg, "ln")) nl.fmt = "%-*jd";
            else if (!strcmp(g.arg, "rn")) nl.fmt = "%*jd";
            else if (!strcmp(g.arg, "rz")) nl.fmt = "%0*jd";
            else {
                fprintf(stderr, "nl: invalid line numbering format: %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto try;
            }
            break;
        case 'd': delimArg = g.arg; break;
        case 1:
            fputs("Usage: nl [OPTION]... [FILE]...\n"
                  "Write each FILE to standard output, with line numbers added.\n\n"
                  "With no FILE, or when FILE is -, read standard input.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -b, --body-numbering=STYLE      use STYLE for numbering body lines\n"
                  "  -d, --section-delimiter=CC      use CC for logical page delimiters\n"
                  "  -f, --footer-numbering=STYLE    use STYLE for numbering footer lines\n"
                  "  -h, --header-numbering=STYLE    use STYLE for numbering header lines\n"
                  "  -i, --line-increment=NUMBER     line number increment at each line\n"
                  "  -l, --join-blank-lines=NUMBER   group of NUMBER empty lines counted as one\n"
                  "  -n, --number-format=FORMAT      insert line numbers according to FORMAT\n"
                  "  -p, --no-renumber               do not reset line numbers for each section\n"
                  "  -s, --number-separator=STRING   add STRING after (possible) line number\n"
                  "  -v, --starting-line-number=NUMBER  first line number for each section\n"
                  "  -w, --number-width=NUMBER       use NUMBER columns for line numbers\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n\n"
                  "Default options are: -bt -d'\\:' -fn -hn -i1 -l1 -n'rn' -s<TAB> -v1 -w6\n\n"
                  "STYLE is one of: a (all lines), t (nonempty lines), n (none), pBRE (lines\n"
                  "matching BRE). FORMAT is one of: ln (left justified), rn (right justified),\n"
                  "rz (right justified, leading zeros).\n",
                  stdout);
            status = 0;
            goto done;
        case 2: puts("nl (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    {
        size_t dl = strlen(delimArg);
        nl.delim = (char *)malloc(dl + 2);
        if (!nl.delim) goto done;
        memcpy(nl.delim, delimArg, dl + 1);
        if (dl == 1) {
            nl.delim[1] = ':';
            nl.delim[2] = '\0';
            dl = 2;
        }
        nl.delimLen = dl;
    }
    nl.lineNo = nl.start;
    status = 0;
    for (int i = 0; i < (g.nops ? g.nops : 1); i++) {
        const char *name = g.nops ? g.ops[i] : "-";
        FILE *in = strcmp(name, "-") ? smallclueAppOpenRead(name) : stdin;
        if (!in) {
            fprintf(stderr, "nl: %s: %s\n", name, strerror(errno));
            status = 1;
            continue;
        }
        bool ok = nlFile(&nl, in);
        if (ferror(in)) {
            fprintf(stderr, "nl: %s: %s\n", name, strerror(errno));
            status = 1;
        }
        if (in != stdin) fclose(in);
        else clearerr(stdin);
        if (!ok) {
            status = 1;
            break;
        }
    }
    goto done;
try:
    status = nlTry();
done:
    for (int k = 0; k < 3; k++)
        if (nl.style[k].haveRe) regfree(&nl.style[k].re);
    free(nl.delim);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        fprintf(stderr, "nl: write error: %s\n", strerror(errno));
        status = 1;
    }
    return status;
}
