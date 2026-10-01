/*
 * uniq: GNU coreutils 9 compatible. -c -d -D -u, --all-repeated[=METHOD]
 * and --group[=METHOD] with their separators, -f -s -w -i -z, the obsolete
 * -N and +N forms (taken in order, as GNU's in-order option scan has them),
 * the INPUT and OUTPUT operands, and GNU's messages. Lines compare as bytes
 * (memcmp, or ASCII case folding with -i), the way uniq 9 does.
 */

#include "uniq_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { UNIQ_DM_NONE, UNIQ_DM_PREPEND, UNIQ_DM_SEPARATE };
enum { UNIQ_GM_NONE, UNIQ_GM_PREPEND, UNIQ_GM_APPEND, UNIQ_GM_SEPARATE, UNIQ_GM_BOTH };

typedef struct {
    size_t skipFields, skipChars, checkChars;
    bool ignoreCase, count;
    bool outUnique, outFirst, outLater;
    int delimitGroups, grouping;
    char delim;
    FILE *out;
} Uniq;

typedef struct {
    char *s;
    size_t len, cap;   /* len counts the delimiter */
} UniqLine;

static int uniqTry(void) {
    fputs("Try 'uniq --help' for more information.\n", stderr);
    return 1;
}

/* One record, its delimiter supplied when the input lacked one. */
static bool uniqRead(FILE *in, char delim, UniqLine *l) {
    l->len = 0;
    int c;
    while ((c = getc(in)) != EOF) {
        if (l->len + 2 > l->cap) {
            size_t cap = l->cap ? l->cap * 2 : 128;
            char *s = (char *)realloc(l->s, cap);
            if (!s) return false;
            l->s = s;
            l->cap = cap;
        }
        l->s[l->len++] = (char)c;
        if (c == delim) return true;
    }
    if (l->len == 0) return false;
    l->s[l->len++] = delim;
    return true;
}

static bool uniqBlank(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n';
}

/* The key: past skipFields fields (blanks, then non-blanks) and skipChars. */
static const char *uniqField(const Uniq *u, const UniqLine *l, size_t *len) {
    size_t size = l->len - 1, i = 0;
    for (size_t n = 0; n < u->skipFields && i < size; n++) {
        while (i < size && uniqBlank((unsigned char)l->s[i])) i++;
        while (i < size && !uniqBlank((unsigned char)l->s[i])) i++;
    }
    i += u->skipChars < size - i ? u->skipChars : size - i;
    *len = size - i;
    return l->s + i;
}

/* glibc's toupper on a byte in the C or UTF-8 locale: ASCII only (Darwin's
 * UTF-8 ctype would fold Latin-1 bytes too). */
static int uniqUpper(int c) {
    return c >= 'a' && c <= 'z' ? c - 32 : c;
}

static bool uniqDifferent(const Uniq *u, const char *a, size_t alen, const char *b, size_t blen) {
    if (u->checkChars < alen) alen = u->checkChars;
    if (u->checkChars < blen) blen = u->checkChars;
    if (alen != blen) return true;
    if (!u->ignoreCase) return memcmp(a, b, alen) != 0;
    for (size_t i = 0; i < alen; i++)
        if (uniqUpper((unsigned char)a[i]) != uniqUpper((unsigned char)b[i])) return true;
    return false;
}

static void uniqWrite(const Uniq *u, const UniqLine *l, bool match, uintmax_t n) {
    if (!(n == 0 ? u->outUnique : !match ? u->outFirst : u->outLater)) return;
    if (u->count) fprintf(u->out, "%7ju ", n + 1);
    fwrite(l->s, 1, l->len, u->out);
}

static void uniqRun(const Uniq *u, FILE *in) {
    UniqLine prev = {0}, cur = {0}, tmp;
    const char *pf = NULL, *cf;
    size_t plen = 0, clen;
    if (u->outUnique && u->outFirst && !u->count) {
        bool printed = false;
        while (uniqRead(in, u->delim, &cur)) {
            cf = uniqField(u, &cur, &clen);
            bool fresh = !pf || uniqDifferent(u, cf, clen, pf, plen);
            if (fresh && u->grouping != UNIQ_GM_NONE &&
                (u->grouping == UNIQ_GM_PREPEND || u->grouping == UNIQ_GM_BOTH ||
                 (printed && (u->grouping == UNIQ_GM_APPEND || u->grouping == UNIQ_GM_SEPARATE))))
                putc(u->delim, u->out);
            if (fresh || u->grouping != UNIQ_GM_NONE) {
                fwrite(cur.s, 1, cur.len, u->out);
                tmp = prev, prev = cur, cur = tmp;
                pf = uniqField(u, &prev, &plen);
                printed = true;
            }
        }
        if ((u->grouping == UNIQ_GM_BOTH || u->grouping == UNIQ_GM_APPEND) && printed) putc(u->delim, u->out);
    } else if (uniqRead(in, u->delim, &prev)) {
        pf = uniqField(u, &prev, &plen);
        uintmax_t matches = 0;
        bool firstDelimiter = true;
        while (uniqRead(in, u->delim, &cur)) {
            cf = uniqField(u, &cur, &clen);
            bool match = !uniqDifferent(u, cf, clen, pf, plen);
            matches += match;
            if (u->delimitGroups != UNIQ_DM_NONE) {
                if (!match) {
                    if (matches) firstDelimiter = false;
                } else if (matches == 1 && (u->delimitGroups == UNIQ_DM_PREPEND ||
                                            (u->delimitGroups == UNIQ_DM_SEPARATE && !firstDelimiter))) {
                    putc(u->delim, u->out);
                }
            }
            if (!match || u->outLater) {
                uniqWrite(u, &prev, match, matches);
                tmp = prev, prev = cur, cur = tmp;
                pf = uniqField(u, &prev, &plen);
                if (!match) matches = 0;
            }
        }
        uniqWrite(u, &prev, false, matches);
    }
    free(prev.s);
    free(cur.s);
}

/* size_opt: a count, saturating; false (after the message) when invalid. */
static bool uniqSize(const char *opt, const char *what, size_t *out) {
    const char *p = opt;
    while (isspace((unsigned char)*p)) p++;
    char *end;
    errno = 0;
    uintmax_t v = *p == '-' ? 0 : strtoumax(opt, &end, 10);
    if (*p == '-' || end == opt || *end) {
        fprintf(stderr, "uniq: %s: %s\n", opt, what);
        return false;
    }
    if (errno == ERANGE || v > SIZE_MAX) v = SIZE_MAX;
    *out = (size_t)v;
    return true;
}

/* argmatch: an exact name or a unique prefix; -1 after the message. */
static int uniqArgmatch(const char *arg, const char *opt, const char *const *names, int n) {
    int found = -1;
    bool ambiguous = false;
    size_t len = strlen(arg);
    for (int i = 0; i < n; i++) {
        if (strncmp(names[i], arg, len)) continue;
        if (strlen(names[i]) == len) return i;
        if (found >= 0) ambiguous = true;
        found = i;
    }
    if (found >= 0 && !ambiguous) return found;
    char q[256], q2[64];
    fprintf(stderr, "uniq: %s argument %s for %s\nValid arguments are:\n", ambiguous ? "ambiguous" : "invalid",
            gnuQuoteLocale(arg, q, sizeof(q)), gnuQuoteLocale(opt, q2, sizeof(q2)));
    for (int i = 0; i < n; i++) fprintf(stderr, "  - %s\n", gnuQuoteLocale(names[i], q, sizeof(q)));
    return -1;
}

static const GnuLongOpt uniqLongs[] = {
    {"count", GNU_NO_ARG, 'c'},        {"repeated", GNU_NO_ARG, 'd'},     {"all-repeated", GNU_OPT_ARG, 'D'},
    {"group", GNU_OPT_ARG, 2},         {"ignore-case", GNU_NO_ARG, 'i'},  {"unique", GNU_NO_ARG, 'u'},
    {"skip-fields", GNU_REQ_ARG, 'f'}, {"skip-chars", GNU_REQ_ARG, 's'},  {"check-chars", GNU_REQ_ARG, 'w'},
    {"zero-terminated", GNU_NO_ARG, 'z'}, {"help", GNU_NO_ARG, 3},       {"version", GNU_NO_ARG, 4},
};

int smallclueUniqCommand(int argc, char **argv) {
    Uniq u = {0, 0, SIZE_MAX, false, false, true, true, false, UNIQ_DM_NONE, UNIQ_GM_NONE, '\n', stdout};
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "uniq", "0123456789Dcdf:is:uw:z", uniqLongs,
                  sizeof(uniqLongs) / sizeof(uniqLongs[0]));
    g.inOrder = true;
    const char *files[2] = {"-", "-"};
    int nfiles = 0, status = 1, c;
    bool outputOption = false, obsoleteFields = false;
    FILE *in = NULL;
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 1: {
            const char *a = g.arg;
            char *end;
            if (!g.done && a[0] == '+' && isdigit((unsigned char)a[1])) {
                errno = 0;
                uintmax_t v = strtoumax(a + 1, &end, 10);
                if (!*end && errno != ERANGE && v <= SIZE_MAX) {
                    u.skipChars = (size_t)v;
                    break;
                }
            }
            if (nfiles == 2) {
                char q[4096];
                fprintf(stderr, "uniq: extra operand %s\n", gnuQuoteLocale(a, q, sizeof(q)));
                goto try;
            }
            files[nfiles++] = a;
            /* POSIXLY_CORRECT: the rest are operands, as GNU uniq has it */
            if (getenv("POSIXLY_CORRECT")) g.done = true;
            break;
        }
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            if (!obsoleteFields) u.skipFields = 0;
            u.skipFields = u.skipFields > (SIZE_MAX - 9) / 10 ? SIZE_MAX : u.skipFields * 10 + (size_t)(c - '0');
            obsoleteFields = true;
            break;
        case 'c': u.count = true; outputOption = true; break;
        case 'd': u.outUnique = false; outputOption = true; break;
        case 'D': {
            u.outUnique = false;
            u.outLater = true;
            outputOption = true;
            if (g.arg) {
                static const char *const m[] = {"none", "prepend", "separate"};
                int k = uniqArgmatch(g.arg, "--all-repeated", m, 3);
                if (k < 0) goto try;
                u.delimitGroups = k;
            }
            break;
        }
        case 2: {
            u.grouping = UNIQ_GM_SEPARATE;
            if (g.arg) {
                static const char *const m[] = {"prepend", "append", "separate", "both"};
                static const int v[] = {UNIQ_GM_PREPEND, UNIQ_GM_APPEND, UNIQ_GM_SEPARATE, UNIQ_GM_BOTH};
                int k = uniqArgmatch(g.arg, "--group", m, 4);
                if (k < 0) goto try;
                u.grouping = v[k];
            }
            break;
        }
        case 'f':
            obsoleteFields = false;
            if (!uniqSize(g.arg, "invalid number of fields to skip", &u.skipFields)) goto done;
            break;
        case 'i': u.ignoreCase = true; break;
        case 's':
            if (!uniqSize(g.arg, "invalid number of bytes to skip", &u.skipChars)) goto done;
            break;
        case 'u': u.outFirst = false; outputOption = true; break;
        case 'w':
            if (!uniqSize(g.arg, "invalid number of bytes to compare", &u.checkChars)) goto done;
            break;
        case 'z': u.delim = '\0'; break;
        case 3:
            fputs("Usage: uniq [OPTION]... [INPUT [OUTPUT]]\n"
                  "Filter adjacent matching lines from INPUT (or standard input),\n"
                  "writing to OUTPUT (or standard output).\n\n"
                  "With no options, matching lines are merged to the first occurrence.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -c, --count           prefix lines by the number of occurrences\n"
                  "  -d, --repeated        only print duplicate lines, one for each group\n"
                  "  -D                    print all duplicate lines\n"
                  "      --all-repeated[=METHOD]  like -D, but allow separating groups\n"
                  "                                 with an empty line;\n"
                  "                                 METHOD={none(default),prepend,separate}\n"
                  "  -f, --skip-fields=N   avoid comparing the first N fields\n"
                  "      --group[=METHOD]  show all items, separating groups with an empty line;\n"
                  "                          METHOD={separate(default),prepend,append,both}\n"
                  "  -i, --ignore-case     ignore differences in case when comparing\n"
                  "  -s, --skip-chars=N    avoid comparing the first N characters\n"
                  "  -u, --unique          only print unique lines\n"
                  "  -z, --zero-terminated     line delimiter is NUL, not newline\n"
                  "  -w, --check-chars=N   compare no more than N characters in lines\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n\n"
                  "A field is a run of blanks (usually spaces and/or TABs), then non-blank\n"
                  "characters.  Fields are skipped before chars.\n",
                  stdout);
            status = 0;
            goto done;
        case 4: puts("uniq (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    if (u.grouping != UNIQ_GM_NONE && outputOption) {
        fputs("uniq: --group is mutually exclusive with -c/-d/-D/-u\n", stderr);
        goto try;
    }
    if (u.count && u.outLater) {
        fputs("uniq: printing all duplicated lines and repeat counts is meaningless\n", stderr);
        goto try;
    }
    if (!strcmp(files[0], "-")) {
        in = stdin;
    } else if (!(in = smallclueAppOpenRead(files[0]))) {
        fprintf(stderr, "uniq: %s: %s\n", files[0], strerror(errno));
        goto done;
    }
    if (strcmp(files[1], "-") && !(u.out = fopen(files[1], "w"))) {
        u.out = stdout;
        fprintf(stderr, "uniq: %s: %s\n", files[1], strerror(errno));
        goto done;
    }
    uniqRun(&u, in);
    status = 0;
    if (ferror(in)) {
        fprintf(stderr, "uniq: %s: %s\n", files[0], strerror(errno));
        status = 1;
    }
    goto done;
try:
    status = uniqTry();
done:
    if (in && in != stdin) fclose(in);
    gnuGetoptFree(&g);
    if ((u.out != stdout ? fclose(u.out) : fflush(stdout)) != 0 && status == 0) {
        gnuWriteError("uniq", errno);
        status = 1;
    }
    return status;
}
