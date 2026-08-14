/* $((...)) arithmetic: C-style integer expressions over long long, with
 * shell variable resolution, assignment operators, ++/--, and ?:.
 * Matches the BusyBox ash feature set. */

#include "sh_interp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ShInterp *interp;
    const char *src;
    size_t pos;
    size_t len;
    bool error;
    char error_msg[128];
} Arith;

static long long parseTernary(Arith *a);

static void arithError(Arith *a, const char *msg) {
    if (!a->error) {
        a->error = true;
        snprintf(a->error_msg, sizeof(a->error_msg), "%s", msg);
    }
}

static void skipWs(Arith *a) {
    while (a->pos < a->len && isspace((unsigned char)a->src[a->pos])) {
        a->pos++;
    }
}

static bool peekOp(Arith *a, const char *op) {
    skipWs(a);
    size_t oplen = strlen(op);
    if (a->pos + oplen > a->len) {
        return false;
    }
    return strncmp(a->src + a->pos, op, oplen) == 0;
}

static bool consumeOp(Arith *a, const char *op) {
    if (peekOp(a, op)) {
        a->pos += strlen(op);
        return true;
    }
    return false;
}

static long long getVar(Arith *a, const char *name) {
    const char *val = shVarGet(a->interp, name);
    if (!val || !*val) {
        return 0;
    }
    /* Variables may hold nested expressions per POSIX; keep it simple:
     * numeric parse with full recursion for plain numbers, one level. */
    char *end = NULL;
    long long v = strtoll(val, &end, 0);
    if (end && *end == '\0') {
        return v;
    }
    /* Recursively evaluate non-numeric values (e.g. x="y+1"). */
    long long result = 0;
    if (a->interp->depth < 32 && shArithEval(a->interp, val, &result) == 0) {
        return result;
    }
    return 0;
}

static void setVar(Arith *a, const char *name, long long value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", value);
    shVarSet(a->interp, name, buf, false);
}

static size_t scanName(Arith *a, char *name, size_t name_len) {
    skipWs(a);
    size_t n = 0;
    size_t p = a->pos;
    if (p < a->len && (isalpha((unsigned char)a->src[p]) || a->src[p] == '_')) {
        while (p < a->len && (isalnum((unsigned char)a->src[p]) || a->src[p] == '_')) {
            if (n < name_len - 1) {
                name[n++] = a->src[p];
            }
            p++;
        }
    }
    name[n] = '\0';
    return p - a->pos;
}

static long long parsePrimary(Arith *a) {
    skipWs(a);
    if (a->pos >= a->len) {
        arithError(a, "unexpected end of expression");
        return 0;
    }
    char c = a->src[a->pos];

    if (c == '(') {
        a->pos++;
        long long v = parseTernary(a);
        skipWs(a);
        if (a->pos < a->len && a->src[a->pos] == ')') {
            a->pos++;
        } else {
            arithError(a, "expected ')'");
        }
        return v;
    }
    if (c == '!') {
        a->pos++;
        return !parsePrimary(a);
    }
    if (c == '~') {
        a->pos++;
        return ~parsePrimary(a);
    }
    if (c == '+' && !peekOp(a, "++")) {
        a->pos++;
        return parsePrimary(a);
    }
    if (c == '-' && !peekOp(a, "--")) {
        a->pos++;
        return -parsePrimary(a);
    }
    if (consumeOp(a, "++")) {
        char name[128];
        size_t adv = scanName(a, name, sizeof(name));
        if (adv == 0) {
            arithError(a, "'++' requires a variable");
            return 0;
        }
        a->pos += adv;
        long long v = getVar(a, name) + 1;
        setVar(a, name, v);
        return v;
    }
    if (consumeOp(a, "--")) {
        char name[128];
        size_t adv = scanName(a, name, sizeof(name));
        if (adv == 0) {
            arithError(a, "'--' requires a variable");
            return 0;
        }
        a->pos += adv;
        long long v = getVar(a, name) - 1;
        setVar(a, name, v);
        return v;
    }

    if (isdigit((unsigned char)c)) {
        char *end = NULL;
        long long v = strtoll(a->src + a->pos, &end, 0);
        if (end == a->src + a->pos) {
            arithError(a, "bad number");
            return 0;
        }
        a->pos = (size_t)(end - a->src);
        return v;
    }

    if (isalpha((unsigned char)c) || c == '_') {
        char name[128];
        size_t adv = scanName(a, name, sizeof(name));
        a->pos += adv;
        /* postfix ++/-- */
        if (peekOp(a, "++")) {
            a->pos += 2;
            long long v = getVar(a, name);
            setVar(a, name, v + 1);
            return v;
        }
        if (peekOp(a, "--")) {
            a->pos += 2;
            long long v = getVar(a, name);
            setVar(a, name, v - 1);
            return v;
        }
        /* assignment operators */
        skipWs(a);
        static const struct {
            const char *op;
            char kind;
        } assigns[] = {
            {"<<=", 'L'}, {">>=", 'R'}, {"+=", '+'}, {"-=", '-'},
            {"*=", '*'}, {"/=", '/'}, {"%=", '%'}, {"&=", '&'},
            {"^=", '^'}, {"|=", '|'},
        };
        for (size_t k = 0; k < sizeof(assigns) / sizeof(assigns[0]); ++k) {
            if (consumeOp(a, assigns[k].op)) {
                long long rhs = parseTernary(a);
                long long cur = getVar(a, name);
                long long v = cur;
                switch (assigns[k].kind) {
                    case '+': v = cur + rhs; break;
                    case '-': v = cur - rhs; break;
                    case '*': v = cur * rhs; break;
                    case '/':
                        if (rhs == 0) { arithError(a, "division by zero"); return 0; }
                        v = cur / rhs;
                        break;
                    case '%':
                        if (rhs == 0) { arithError(a, "division by zero"); return 0; }
                        v = cur % rhs;
                        break;
                    case '&': v = cur & rhs; break;
                    case '^': v = cur ^ rhs; break;
                    case '|': v = cur | rhs; break;
                    case 'L': v = cur << rhs; break;
                    case 'R': v = cur >> rhs; break;
                }
                setVar(a, name, v);
                return v;
            }
        }
        if (peekOp(a, "=") && !peekOp(a, "==")) {
            a->pos += 1;
            long long v = parseTernary(a);
            setVar(a, name, v);
            return v;
        }
        return getVar(a, name);
    }

    if (c == '$') {
        /* Shouldn't normally appear (executor pre-expands), but handle $name. */
        a->pos++;
        char name[128];
        size_t adv = scanName(a, name, sizeof(name));
        if (adv > 0) {
            a->pos += adv;
            return getVar(a, name);
        }
        arithError(a, "bad '$' in expression");
        return 0;
    }

    arithError(a, "syntax error in expression");
    return 0;
}

static long long parseMul(Arith *a) {
    long long v = parsePrimary(a);
    for (;;) {
        if (consumeOp(a, "*")) {
            v *= parsePrimary(a);
        } else if (peekOp(a, "/") && !peekOp(a, "/=")) {
            a->pos++;
            long long rhs = parsePrimary(a);
            if (rhs == 0) {
                arithError(a, "division by zero");
                return 0;
            }
            v /= rhs;
        } else if (peekOp(a, "%") && !peekOp(a, "%=")) {
            a->pos++;
            long long rhs = parsePrimary(a);
            if (rhs == 0) {
                arithError(a, "division by zero");
                return 0;
            }
            v %= rhs;
        } else {
            return v;
        }
    }
}

static long long parseAdd(Arith *a) {
    long long v = parseMul(a);
    for (;;) {
        skipWs(a);
        if (peekOp(a, "+") && !peekOp(a, "++") && !peekOp(a, "+=")) {
            a->pos++;
            v += parseMul(a);
        } else if (peekOp(a, "-") && !peekOp(a, "--") && !peekOp(a, "-=")) {
            a->pos++;
            v -= parseMul(a);
        } else {
            return v;
        }
    }
}

static long long parseShift(Arith *a) {
    long long v = parseAdd(a);
    for (;;) {
        if (peekOp(a, "<<") && !peekOp(a, "<<=")) {
            a->pos += 2;
            v <<= parseAdd(a);
        } else if (peekOp(a, ">>") && !peekOp(a, ">>=")) {
            a->pos += 2;
            v >>= parseAdd(a);
        } else {
            return v;
        }
    }
}

static long long parseRel(Arith *a) {
    long long v = parseShift(a);
    for (;;) {
        if (consumeOp(a, "<=")) {
            v = v <= parseShift(a);
        } else if (consumeOp(a, ">=")) {
            v = v >= parseShift(a);
        } else if (peekOp(a, "<") && !peekOp(a, "<<")) {
            a->pos++;
            v = v < parseShift(a);
        } else if (peekOp(a, ">") && !peekOp(a, ">>")) {
            a->pos++;
            v = v > parseShift(a);
        } else {
            return v;
        }
    }
}

static long long parseEq(Arith *a) {
    long long v = parseRel(a);
    for (;;) {
        if (consumeOp(a, "==")) {
            v = v == parseRel(a);
        } else if (consumeOp(a, "!=")) {
            v = v != parseRel(a);
        } else {
            return v;
        }
    }
}

static long long parseBitAnd(Arith *a) {
    long long v = parseEq(a);
    while (peekOp(a, "&") && !peekOp(a, "&&") && !peekOp(a, "&=")) {
        a->pos++;
        v &= parseEq(a);
    }
    return v;
}

static long long parseBitXor(Arith *a) {
    long long v = parseBitAnd(a);
    while (peekOp(a, "^") && !peekOp(a, "^=")) {
        a->pos++;
        v ^= parseBitAnd(a);
    }
    return v;
}

static long long parseBitOr(Arith *a) {
    long long v = parseBitXor(a);
    while (peekOp(a, "|") && !peekOp(a, "||") && !peekOp(a, "|=")) {
        a->pos++;
        v |= parseBitXor(a);
    }
    return v;
}

static long long parseLogAnd(Arith *a) {
    long long v = parseBitOr(a);
    while (consumeOp(a, "&&")) {
        long long rhs = parseBitOr(a);
        v = (v != 0) && (rhs != 0);
    }
    return v;
}

static long long parseLogOr(Arith *a) {
    long long v = parseLogAnd(a);
    while (consumeOp(a, "||")) {
        long long rhs = parseLogAnd(a);
        v = (v != 0) || (rhs != 0);
    }
    return v;
}

static long long parseTernary(Arith *a) {
    long long cond = parseLogOr(a);
    skipWs(a);
    if (a->pos < a->len && a->src[a->pos] == '?') {
        a->pos++;
        long long then_v = parseTernary(a);
        skipWs(a);
        if (a->pos < a->len && a->src[a->pos] == ':') {
            a->pos++;
        } else {
            arithError(a, "expected ':' in ?:");
        }
        long long else_v = parseTernary(a);
        return cond ? then_v : else_v;
    }
    return cond;
}

int shArithEval(ShInterp *interp, const char *expr, long long *result) {
    if (!expr) {
        if (result) {
            *result = 0;
        }
        return 0;
    }

    /* Pre-expand $var, ${...}, $(...) in the expression text. */
    char *expanded = NULL;
    if (strchr(expr, '$') || strchr(expr, '`')) {
        expanded = shExpandHereDocument(interp, expr);
        if (!expanded) {
            return 1;
        }
        expr = expanded;
    }

    Arith a;
    memset(&a, 0, sizeof(a));
    a.interp = interp;
    a.src = expr;
    a.len = strlen(expr);
    interp->depth++;

    long long v = 0;
    skipWs(&a);
    if (a.pos >= a.len) {
        v = 0; /* empty expression is 0 */
    } else {
        v = parseTernary(&a);
        /* comma operator */
        skipWs(&a);
        while (!a.error && a.pos < a.len && a.src[a.pos] == ',') {
            a.pos++;
            v = parseTernary(&a);
            skipWs(&a);
        }
        skipWs(&a);
        if (!a.error && a.pos < a.len) {
            arithError(&a, "trailing characters in expression");
        }
    }
    interp->depth--;
    free(expanded);

    if (a.error) {
        fprintf(stderr, "sh: arithmetic: %s\n", a.error_msg);
        return 1;
    }
    if (result) {
        *result = v;
    }
    return 0;
}
