/*
 * expr(1): POSIX arithmetic/string-comparison evaluator. Shell scripts
 * (autoconf-style configure scripts especially) rely on `expr` for
 * portable arithmetic and pattern matching where `$(( ))` isn't assumed
 * available; there was no applet for it before this.
 *
 * Grammar (POSIX, lowest to highest precedence):
 *   or_expr   := and_expr ( '|' and_expr )*
 *   and_expr  := cmp_expr ( '&' cmp_expr )*
 *   cmp_expr  := add_expr ( (= == != < <= > >=) add_expr )*
 *   add_expr  := mul_expr ( (+ -) mul_expr )*
 *   mul_expr  := colon_expr ( (* / %) colon_expr )*
 *   colon_expr:= primary ( ':' primary )*
 *   primary   := NUMBER | STRING | '(' or_expr ')'
 *              | 'length' STRING | 'index' STRING STRING
 *              | 'substr' STRING STRING STRING | 'match' STRING STRING
 */

#include "expr_app.h"

#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **tokens;
    int count;
    int pos;
} ExprParser;

static const char *exprPeek(ExprParser *p) {
    return (p->pos < p->count) ? p->tokens[p->pos] : NULL;
}

static const char *exprNext(ExprParser *p) {
    return (p->pos < p->count) ? p->tokens[p->pos++] : NULL;
}

static bool exprIsInteger(const char *s, long long *out) {
    if (!s || !*s) return false;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return false;
    if (out) *out = v;
    return true;
}

/* POSIX: an expression is "false" if it is the null string or the
 * numeric value 0 (including forms like "-0" or "00"). */
static bool exprIsFalsey(const char *s) {
    if (!s || s[0] == '\0') return true;
    long long v;
    if (exprIsInteger(s, &v) && v == 0) return true;
    return false;
}

static char *exprDup(const char *s) {
    return strdup(s ? s : "");
}

static char *exprFormatInt(long long v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", v);
    return strdup(buf);
}

/* BRE match of STRING against REGEXP, anchored at the beginning per
 * POSIX expr semantics. If REGEXP contains a \(...\) group, the result
 * is the group's matched text (empty string on no match); otherwise the
 * result is the count of matched characters (0 on no match). */
static char *smallclueExprMatch(const char *s, const char *pattern, int *err) {
    if (!s) s = "";
    if (!pattern) pattern = "";
    size_t patLen = strlen(pattern);
    char *anchored = (char *)malloc(patLen + 2);
    anchored[0] = '^';
    memcpy(anchored + 1, pattern, patLen);
    anchored[patLen + 1] = '\0';

    regex_t re;
    int rc = regcomp(&re, anchored, 0); /* BRE: \( \) groups, no REG_EXTENDED */
    free(anchored);
    if (rc != 0) {
        fprintf(stderr, "expr: invalid regular expression\n");
        *err = 2;
        return exprDup("");
    }

    bool hasGroups = (re.re_nsub > 0);
    regmatch_t matches[10];
    int mrc = regexec(&re, s, 10, matches, 0);
    char *result;
    if (mrc != 0) {
        result = exprDup(hasGroups ? "" : "0");
    } else if (hasGroups) {
        regmatch_t g = matches[1];
        if (g.rm_so < 0) {
            result = exprDup("");
        } else {
            size_t len = (size_t)(g.rm_eo - g.rm_so);
            result = (char *)malloc(len + 1);
            memcpy(result, s + g.rm_so, len);
            result[len] = '\0';
        }
    } else {
        result = exprFormatInt((long long)(matches[0].rm_eo - matches[0].rm_so));
    }
    regfree(&re);
    return result;
}

static char *exprParseOr(ExprParser *p, int *err);

static char *exprParsePrimary(ExprParser *p, int *err) {
    const char *tok = exprPeek(p);
    if (!tok) {
        *err = 2;
        return exprDup("");
    }

    if (strcmp(tok, "(") == 0) {
        exprNext(p);
        char *inner = exprParseOr(p, err);
        const char *close = exprNext(p);
        if (!close || strcmp(close, ")") != 0) {
            fprintf(stderr, "expr: syntax error: expected ')'\n");
            *err = 2;
        }
        return inner;
    }
    if (strcmp(tok, "length") == 0 && (p->count - p->pos) >= 2) {
        exprNext(p);
        const char *s = exprNext(p);
        return exprFormatInt((long long)strlen(s ? s : ""));
    }
    if (strcmp(tok, "index") == 0 && (p->count - p->pos) >= 3) {
        exprNext(p);
        const char *s = exprNext(p);
        const char *chars = exprNext(p);
        size_t idx = 0;
        if (s && chars) {
            for (size_t i = 0; s[i]; i++) {
                if (strchr(chars, s[i])) { idx = i + 1; break; }
            }
        }
        return exprFormatInt((long long)idx);
    }
    if (strcmp(tok, "substr") == 0 && (p->count - p->pos) >= 4) {
        exprNext(p);
        const char *s = exprNext(p);
        const char *posTok = exprNext(p);
        const char *lenTok = exprNext(p);
        long long startPos = 0, length = 0;
        if (!exprIsInteger(posTok, &startPos) || !exprIsInteger(lenTok, &length)) {
            fprintf(stderr, "expr: non-numeric argument to substr\n");
            *err = 2;
            return exprDup("");
        }
        size_t slen = s ? strlen(s) : 0;
        if (startPos < 1 || length < 0 || (size_t)(startPos - 1) >= slen) {
            return exprDup("");
        }
        size_t begin = (size_t)(startPos - 1);
        size_t avail = slen - begin;
        size_t take = (size_t)length;
        if (take > avail) take = avail;
        char *out = (char *)malloc(take + 1);
        memcpy(out, s + begin, take);
        out[take] = '\0';
        return out;
    }
    if (strcmp(tok, "match") == 0 && (p->count - p->pos) >= 3) {
        exprNext(p);
        const char *s = exprNext(p);
        const char *pattern = exprNext(p);
        return smallclueExprMatch(s, pattern, err);
    }

    exprNext(p);
    return exprDup(tok);
}

static char *exprParseColon(ExprParser *p, int *err) {
    char *left = exprParsePrimary(p, err);
    while (exprPeek(p) && strcmp(exprPeek(p), ":") == 0) {
        exprNext(p);
        char *right = exprParsePrimary(p, err);
        char *result = smallclueExprMatch(left, right, err);
        free(left);
        free(right);
        left = result;
    }
    return left;
}

static char *exprParseMul(ExprParser *p, int *err) {
    char *left = exprParseColon(p, err);
    for (;;) {
        const char *op = exprPeek(p);
        if (!op || !(strcmp(op, "*") == 0 || strcmp(op, "/") == 0 || strcmp(op, "%") == 0)) break;
        exprNext(p);
        char *right = exprParseColon(p, err);
        long long a, b;
        if (!exprIsInteger(left, &a) || !exprIsInteger(right, &b)) {
            fprintf(stderr, "expr: non-numeric argument\n");
            *err = 2;
            free(left);
            free(right);
            left = exprDup("0");
            continue;
        }
        long long v;
        if (op[0] == '*') {
            v = a * b;
        } else if (b == 0) {
            fprintf(stderr, "expr: division by zero\n");
            *err = 2;
            free(left);
            free(right);
            return exprDup("0");
        } else {
            v = (op[0] == '/') ? a / b : a % b;
        }
        free(left);
        free(right);
        left = exprFormatInt(v);
    }
    return left;
}

static char *exprParseAdd(ExprParser *p, int *err) {
    char *left = exprParseMul(p, err);
    for (;;) {
        const char *op = exprPeek(p);
        if (!op || !(strcmp(op, "+") == 0 || strcmp(op, "-") == 0)) break;
        exprNext(p);
        char *right = exprParseMul(p, err);
        long long a, b;
        if (!exprIsInteger(left, &a) || !exprIsInteger(right, &b)) {
            fprintf(stderr, "expr: non-numeric argument\n");
            *err = 2;
            free(left);
            free(right);
            return exprDup("0");
        }
        long long v = (op[0] == '+') ? (a + b) : (a - b);
        free(left);
        free(right);
        left = exprFormatInt(v);
    }
    return left;
}

static char *exprParseCompare(ExprParser *p, int *err) {
    char *left = exprParseAdd(p, err);
    for (;;) {
        const char *op = exprPeek(p);
        bool isCmp = op && (strcmp(op, "=") == 0 || strcmp(op, "==") == 0 ||
                            strcmp(op, "!=") == 0 || strcmp(op, "<") == 0 ||
                            strcmp(op, "<=") == 0 || strcmp(op, ">") == 0 ||
                            strcmp(op, ">=") == 0);
        if (!isCmp) break;
        char opBuf[3];
        strncpy(opBuf, op, 2);
        opBuf[2] = '\0';
        exprNext(p);
        char *right = exprParseAdd(p, err);
        int cmp;
        long long a, b;
        if (exprIsInteger(left, &a) && exprIsInteger(right, &b)) {
            cmp = (a < b) ? -1 : (a > b) ? 1 : 0;
        } else {
            int c = strcmp(left, right);
            cmp = (c < 0) ? -1 : (c > 0) ? 1 : 0;
        }
        bool result;
        if (strcmp(opBuf, "=") == 0 || strcmp(op, "==") == 0) result = (cmp == 0);
        else if (strcmp(op, "!=") == 0) result = (cmp != 0);
        else if (strcmp(op, "<=") == 0) result = (cmp <= 0);
        else if (strcmp(op, "<") == 0) result = (cmp < 0);
        else if (strcmp(op, ">=") == 0) result = (cmp >= 0);
        else result = (cmp > 0);
        free(left);
        free(right);
        left = exprDup(result ? "1" : "0");
    }
    return left;
}

static char *exprParseAnd(ExprParser *p, int *err) {
    char *left = exprParseCompare(p, err);
    while (exprPeek(p) && strcmp(exprPeek(p), "&") == 0) {
        exprNext(p);
        char *right = exprParseCompare(p, err);
        if (exprIsFalsey(left) || exprIsFalsey(right)) {
            free(left);
            free(right);
            left = exprDup("0");
        } else {
            free(right);
        }
    }
    return left;
}

static char *exprParseOr(ExprParser *p, int *err) {
    char *left = exprParseAnd(p, err);
    while (exprPeek(p) && strcmp(exprPeek(p), "|") == 0) {
        exprNext(p);
        char *right = exprParseAnd(p, err);
        if (!exprIsFalsey(left)) {
            free(right);
        } else {
            free(left);
            left = right;
        }
    }
    return left;
}

int smallclueExprCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "expr: missing operand\n");
        return 2;
    }
    ExprParser parser = { argv + 1, argc - 1, 0 };
    int err = 0;
    char *result = exprParseOr(&parser, &err);
    if (parser.pos < parser.count) {
        fprintf(stderr, "expr: syntax error\n");
        free(result);
        return 2;
    }
    if (err) {
        free(result);
        return 2;
    }
    printf("%s\n", result);
    int exitCode = exprIsFalsey(result) ? 1 : 0;
    free(result);
    return exitCode;
}
