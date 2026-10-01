/*
 * tr: GNU coreutils 9 compatible. Backslash escapes (\ooo, \a..\v, \\),
 * ranges, [:class:], [=c=], [c*n] and [c*], -c/-C -d -s -t, set2 padded
 * with its last character, [:lower:]/[:upper:] case mapping with GNU's
 * alignment rule, every validation message GNU gives, and options ending
 * at the first operand (so `tr a -d` maps 'a' to '-').
 */

#include "tr_app.h"

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

enum { TR_CHAR, TR_RANGE, TR_CLASS, TR_EQUIV, TR_REPEAT };

static const char *const trClassNames[] = {"alnum", "alpha", "blank", "cntrl", "digit", "graph",
                                           "lower", "print", "punct", "space", "upper", "xdigit"};
enum { TR_C_LOWER = 6, TR_C_UPPER = 10 };

typedef struct {
    int kind;
    unsigned char a, b;   /* CHAR/EQUIV/REPEAT: a; RANGE: a-b */
    int cls;
    uintmax_t count;      /* REPEAT */
    bool fill;            /* REPEAT [c*] */
} TrElem;

typedef struct {
    TrElem *v;
    size_t n;
    unsigned char *chars;  /* expanded */
    size_t len;
    size_t *classAt;       /* per expanded char: 1 + class element index starting there, else 0 */
} TrSet;

/* As glibc classifies a byte in the C and UTF-8 locales: nothing above
 * 0x7f. (Darwin's UTF-8 ctype calls 0xe0 a lower-case letter, which made
 * [:lower:] and [:upper:] different sizes.) */
static bool trClassHas(int cls, int c) {
    if (c >= 0x80) return false;
    switch (cls) {
    case 0: return isalnum(c);
    case 1: return isalpha(c);
    case 2: return c == ' ' || c == '\t';
    case 3: return iscntrl(c);
    case 4: return isdigit(c);
    case 5: return isgraph(c);
    case 6: return islower(c);
    case 7: return isprint(c);
    case 8: return ispunct(c);
    case 9: return isspace(c);
    case 10: return isupper(c);
    default: return isxdigit(c);
    }
}

static int trFail(const char *msg) {
    fprintf(stderr, "tr: %s\n", msg);
    return 1;
}

/* GNU's unquote: the string as values, each marked escaped or not. */
static size_t trUnescape(const char *s, unsigned char *val, bool *esc) {
    size_t n = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] != '\\') {
            val[n] = (unsigned char)s[i];
            esc[n++] = false;
            continue;
        }
        esc[n] = true;
        char c = s[++i];
        switch (c) {
        case 'a': val[n++] = '\a'; break;
        case 'b': val[n++] = '\b'; break;
        case 'f': val[n++] = '\f'; break;
        case 'n': val[n++] = '\n'; break;
        case 'r': val[n++] = '\r'; break;
        case 't': val[n++] = '\t'; break;
        case 'v': val[n++] = '\v'; break;
        case '\0':
            fputs("tr: warning: an unescaped backslash at end of string is not portable\n", stderr);
            val[n] = '\\';
            esc[n++] = false;
            i--;
            break;
        default:
            if (c >= '0' && c <= '7') {
                int v = c - '0';
                for (int k = 0; k < 2 && s[i + 1] >= '0' && s[i + 1] <= '7'; k++) {
                    int w = v * 8 + (s[i + 1] - '0');
                    if (w > 255) {
                        /* GNU: a third digit that would overflow is not consumed */
                        break;
                    }
                    v = w;
                    i++;
                }
                val[n++] = (unsigned char)v;
            } else {
                val[n++] = (unsigned char)c;
            }
        }
    }
    return n;
}

static bool trParse(const char *spec, TrSet *set) {
    size_t slen = strlen(spec);
    unsigned char *val = (unsigned char *)malloc(slen + 1);
    bool *esc = (bool *)malloc((slen + 1) * sizeof(bool));
    set->v = (TrElem *)calloc(slen + 1, sizeof(TrElem));
    set->n = 0;
    bool ok = val && esc && set->v;
    size_t n = ok ? trUnescape(spec, val, esc) : 0;
    char q[512];
    for (size_t i = 0; ok && i < n;) {
        TrElem *e = &set->v[set->n];
        if (val[i] == '[' && !esc[i] && i + 1 < n) {
            if ((val[i + 1] == ':' || val[i + 1] == '=') && !esc[i + 1]) {
                unsigned char d = val[i + 1];
                size_t j = i + 2;
                while (j + 1 < n && !(val[j] == d && !esc[j] && val[j + 1] == ']' && !esc[j + 1])) j++;
                if (j + 1 < n && j > i + 2) {
                    size_t len = j - (i + 2);
                    if (d == ':') {
                        char name[32] = "";
                        int cls = -1;
                        if (len < sizeof(name)) {
                            memcpy(name, val + i + 2, len);
                            name[len] = '\0';
                            for (int k = 0; k < 12; k++)
                                if (!strcmp(name, trClassNames[k])) cls = k;
                        }
                        if (cls < 0) {
                            char raw[512];
                            snprintf(raw, sizeof(raw), "%.*s", (int)len, (const char *)val + i + 2);
                            fprintf(stderr, "tr: invalid character class %s\n", gnuQuoteLocale(raw, q, sizeof(q)));
                            ok = false;
                            break;
                        }
                        e->kind = TR_CLASS;
                        e->cls = cls;
                    } else {
                        if (len != 1) {
                            fprintf(stderr, "tr: %.*s: equivalence class operand must be a single character\n",
                                    (int)len, (const char *)val + i + 2);
                            ok = false;
                            break;
                        }
                        e->kind = TR_EQUIV;
                        e->a = val[i + 2];
                    }
                    set->n++;
                    i = j + 2;
                    continue;
                }
            } else if (i + 2 < n && val[i + 2] == '*' && !esc[i + 2]) {
                size_t j = i + 3;
                while (j < n && !(val[j] == ']' && !esc[j])) j++;
                if (j < n) {
                    size_t len = j - (i + 3);
                    char digits[512];
                    snprintf(digits, sizeof(digits), "%.*s", (int)len, (const char *)val + i + 3);
                    e->kind = TR_REPEAT;
                    e->a = val[i + 1];
                    if (len == 0) {
                        e->fill = true;
                    } else {
                        char *end;
                        errno = 0;
                        uintmax_t c = strtoumax(digits, &end, digits[0] == '0' ? 8 : 10);
                        bool digitsOnly = true;
                        for (size_t k = 0; k < len; k++)
                            if (!isdigit((unsigned char)digits[k])) digitsOnly = false;
                        if (!digitsOnly || *end || errno == ERANGE || c > SIZE_MAX / 2) {
                            fprintf(stderr, "tr: invalid repeat count %s in [c*n] construct\n",
                                    gnuQuoteLocale(digits, q, sizeof(q)));
                            ok = false;
                            break;
                        }
                        e->count = c;
                        e->fill = c == 0;
                    }
                    set->n++;
                    i = j + 1;
                    continue;
                }
            }
        }
        if (i + 2 < n && val[i + 1] == '-' && !esc[i + 1]) {
            if (val[i + 2] < val[i]) {
                char raw[16], lo[5], hi[5];   /* make_printable_char: \ooo for the unprintable */
                snprintf(lo, sizeof(lo), isprint(val[i]) ? "%c" : "\\%03o", val[i]);
                snprintf(hi, sizeof(hi), isprint(val[i + 2]) ? "%c" : "\\%03o", val[i + 2]);
                snprintf(raw, sizeof(raw), "%s-%s", lo, hi);
                fprintf(stderr, "tr: range-endpoints of '%s' are in reverse collating sequence order\n", raw);
                ok = false;
                break;
            }
            e->kind = TR_RANGE;
            e->a = val[i];
            e->b = val[i + 2];
            set->n++;
            i += 3;
            continue;
        }
        e->kind = TR_CHAR;
        e->a = val[i++];
        set->n++;
    }
    free(val);
    free(esc);
    return ok;
}

/* The set's characters in order; a fill repeat gets `fill` copies. */
static bool trExpand(TrSet *set, size_t fill) {
    size_t cap = 0;
    for (size_t i = 0; i < set->n; i++) {
        const TrElem *e = &set->v[i];
        cap += e->kind == TR_RANGE ? (size_t)(e->b - e->a) + 1
               : e->kind == TR_CLASS ? 256
               : e->kind == TR_REPEAT ? (e->fill ? fill : (size_t)e->count)
                                      : 1;
    }
    set->chars = (unsigned char *)malloc(cap + 1);
    set->classAt = (size_t *)calloc(cap + 1, sizeof(size_t));
    if (!set->chars || !set->classAt) return false;
    size_t n = 0;
    for (size_t i = 0; i < set->n; i++) {
        const TrElem *e = &set->v[i];
        switch (e->kind) {
        case TR_RANGE:
            for (int c = e->a; c <= e->b; c++) set->chars[n++] = (unsigned char)c;
            break;
        case TR_CLASS:
            set->classAt[n] = i + 1;
            for (int c = 0; c < 256; c++)
                if (trClassHas(e->cls, c)) set->chars[n++] = (unsigned char)c;
            break;
        case TR_REPEAT:
            for (size_t k = 0, m = e->fill ? fill : (size_t)e->count; k < m; k++) set->chars[n++] = e->a;
            break;
        default: set->chars[n++] = e->a; break;
        }
    }
    set->len = n;
    return true;
}

static void trFree(TrSet *s) {
    free(s->v);
    free(s->chars);
    free(s->classAt);
}

static const GnuLongOpt trLongs[] = {
    {"complement", GNU_NO_ARG, 'c'}, {"delete", GNU_NO_ARG, 'd'}, {"squeeze-repeats", GNU_NO_ARG, 's'},
    {"truncate-set1", GNU_NO_ARG, 't'}, {"help", GNU_NO_ARG, 3}, {"version", GNU_NO_ARG, 4},
};

int smallclueTrCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "tr", "+AcCdst", trLongs, sizeof(trLongs) / sizeof(trLongs[0]));
    g.inOrder = true;
    bool complement = false, del = false, squeeze = false, truncate = false;
    const char *ops[3];
    int nops = 0, status = 1, c;
    char q[4096];
    TrSet s1 = {0}, s2 = {0};
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 1:
            if (nops < 3) ops[nops++] = g.arg;
            else nops++;
            g.done = true;   /* options end at the first operand */
            break;
        case 'A': break;
        case 'c': case 'C': complement = true; break;
        case 'd': del = true; break;
        case 's': squeeze = true; break;
        case 't': truncate = true; break;
        case 3:
            fputs("Usage: tr [OPTION]... STRING1 [STRING2]\n"
                  "Translate, squeeze, and/or delete characters from standard input,\n"
                  "writing to standard output.  STRING1 and STRING2 specify arrays of\n"
                  "characters ARRAY1 and ARRAY2 that control the action.\n\n"
                  "  -c, -C, --complement    use the complement of ARRAY1\n"
                  "  -d, --delete            delete characters in ARRAY1, do not translate\n"
                  "  -s, --squeeze-repeats   replace each sequence of a repeated character\n"
                  "                            that is listed in the last specified ARRAY,\n"
                  "                            with a single occurrence of that character\n"
                  "  -t, --truncate-set1     first truncate ARRAY1 to length of ARRAY2\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n\n"
                  "ARRAYs are specified as strings of characters: \\NNN \\\\ \\a \\b \\f \\n \\r \\t \\v,\n"
                  "CHAR1-CHAR2, [CHAR*], [CHAR*REPEAT], [:CLASS:] and [=CHAR=].\n",
                  stdout);
            status = 0;
            goto done;
        case 4:
            puts("tr (SmallCLUE) 9.4");
            status = 0;
            goto done;
        default:
            goto try;
        }
    }
    {
        bool translating = nops >= 2 && !del;
        int need = del == squeeze ? 2 : 1;   /* -ds and plain translate: two */
        if (nops == 0) {
            fputs("tr: missing operand\n", stderr);
            goto try;
        }
        if (nops < need) {
            fprintf(stderr, "tr: missing operand after %s\n", gnuQuoteLocale(ops[nops - 1], q, sizeof(q)));
            fputs(squeeze ? "Two strings must be given when both deleting and squeezing repeats.\n"
                          : "Two strings must be given when translating.\n",
                  stderr);
            goto try;
        }
        int most = del && !squeeze ? 1 : 2;
        if (nops > most) {
            fprintf(stderr, "tr: extra operand %s\n", gnuQuoteLocale(ops[most], q, sizeof(q)));
            if (del && !squeeze) fputs("Only one string may be given when deleting without squeezing repeats.\n", stderr);
            goto try;
        }
        if (!trParse(ops[0], &s1)) goto done;
        if (nops > 1 && !trParse(ops[1], &s2)) goto done;
        size_t s1fill = 0, s2fills = 0;
        bool s1class = false, s2equiv = false, s2restricted = false;
        for (size_t i = 0; i < s1.n; i++) {
            if (s1.v[i].kind == TR_REPEAT && s1.v[i].fill) s1fill++;
            if (s1.v[i].kind == TR_CLASS) s1class = true;
        }
        if (s1fill) {
            status = trFail("the [c*] repeat construct may not appear in string1");
            goto done;
        }
        trExpand(&s1, 0);
        unsigned char inSet1[256] = {0};
        for (size_t i = 0; i < s1.len; i++) inSet1[s1.chars[i]] = 1;
        size_t len1 = s1.len;
        if (complement) {
            len1 = 0;
            for (int k = 0; k < 256; k++) len1 += !inSet1[k];
        }
        if (nops > 1) {
            size_t fixed = 0;
            for (size_t i = 0; i < s2.n; i++) {
                const TrElem *e = &s2.v[i];
                if (e->kind == TR_REPEAT && e->fill) s2fills++;
                else if (e->kind == TR_RANGE) fixed += (size_t)(e->b - e->a) + 1;
                else if (e->kind == TR_REPEAT) fixed += (size_t)e->count;
                else if (e->kind == TR_CLASS) {
                    for (int k = 0; k < 256; k++) fixed += trClassHas(e->cls, k);
                    if (e->cls != TR_C_LOWER && e->cls != TR_C_UPPER) s2restricted = true;
                } else fixed++;
                if (e->kind == TR_EQUIV) s2equiv = true;
            }
            if (s2fills > 1) {
                status = trFail("only one [c*] repeat construct may appear in string2");
                goto done;
            }
            if (translating) {
                if (s2equiv) {
                    status = trFail("[=c=] expressions may not appear in string2 when translating");
                    goto done;
                }
                if (s2restricted) {
                    status = trFail("when translating, the only character classes that may appear in\n"
                                    "string2 are 'upper' and 'lower'");
                    goto done;
                }
            } else if (s2fills) {
                status = trFail("the [c*] construct may appear in string2 only when translating");
                goto done;
            }
            trExpand(&s2, len1 > fixed ? len1 - fixed : 0);
            /* GNU's validate_case_classes: where string2 starts [:upper:] or
             * [:lower:], string1 must start one too (not checked with -c, nor
             * more than one past string1's end). */
            if (translating && !complement) {
                for (size_t o = 0; o < s2.len && o <= s1.len; o++) {   /* GNU looks one past */
                    if (!s2.classAt[o]) continue;
                    size_t e1 = o < s1.len ? s1.classAt[o] : 0;
                    int cls1 = e1 ? s1.v[e1 - 1].cls : -1;
                    if (cls1 != TR_C_LOWER && cls1 != TR_C_UPPER) {
                        status = trFail("misaligned [:upper:] and/or [:lower:] construct");
                        goto done;
                    }
                }
            }
            if (translating && len1 > s2.len && !truncate) {
                if (s2.len == 0) {
                    status = trFail("when not truncating set1, string2 must be non-empty");
                    goto done;
                }
                if (s2.n && s2.v[s2.n - 1].kind == TR_CLASS) {
                    status = trFail("when translating with string1 longer than string2,\n"
                                    "the latter string must not end with a character class");
                    goto done;
                }
            }
            if (translating && complement && s1class) {
                size_t padded = !truncate && s2.len < len1 ? len1 : s2.len;   /* after set2 is extended */
                bool same = padded == len1;
                for (size_t i = 1; same && i < s2.len; i++) same = s2.chars[i] == s2.chars[0];
                if (!same) {
                    status = trFail("when translating with complemented character classes,\n"
                                    "string2 must map all characters in the domain to one");
                    goto done;
                }
            }
        }
        unsigned char map[256], delSet[256] = {0}, sqSet[256] = {0};
        for (int k = 0; k < 256; k++) map[k] = (unsigned char)k;
        if (translating) {
            unsigned char order[256];
            size_t n1 = 0;
            if (complement) {
                for (int k = 0; k < 256; k++)
                    if (!inSet1[k]) order[n1++] = (unsigned char)k;
            }
            const unsigned char *src = complement ? order : s1.chars;
            if (truncate && n1 == 0 && !complement) n1 = s1.len < s2.len ? s1.len : s2.len;
            else if (!complement) n1 = s1.len;
            else if (truncate && s2.len < n1) n1 = s2.len;
            for (size_t i = 0; i < n1; i++)
                map[src[i]] = i < s2.len ? s2.chars[i] : s2.chars[s2.len - 1];
            if (squeeze)
                for (size_t i = 0; i < s2.len; i++) sqSet[s2.chars[i]] = 1;
        } else {
            for (int k = 0; k < 256; k++) {
                bool in = inSet1[k] != complement;
                if (del) delSet[k] = in;
                else if (squeeze) sqSet[k] = in;
            }
            if (del && squeeze)
                for (size_t i = 0; i < s2.len; i++) sqSet[s2.chars[i]] = 1;
        }
        unsigned char in[65536], out[65536];
        size_t got;
        int last = -1;
        while ((got = fread(in, 1, sizeof(in), stdin)) > 0) {
            size_t o = 0;
            for (size_t i = 0; i < got; i++) {
                unsigned char ch = in[i];
                if (delSet[ch]) continue;
                ch = map[ch];
                if (sqSet[ch] && last == ch) continue;
                last = ch;
                out[o++] = ch;
            }
            if (o && fwrite(out, 1, o, stdout) != o) break;
        }
        if (ferror(stdin)) {
            fprintf(stderr, "tr: read error: %s\n", strerror(errno));
            goto done;
        }
        status = 0;
        goto done;
    }
try:
    fputs("Try 'tr --help' for more information.\n", stderr);
    status = 1;
done:
    trFree(&s1);
    trFree(&s2);
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        fprintf(stderr, "tr: write error: %s\n", strerror(errno));
        status = 1;
    }
    return status;
}
