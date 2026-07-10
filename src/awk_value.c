/*
 * AWK value model: the classic uninitialized/number/string/"strnum"
 * tagged type, with POSIX comparison and truthiness rules. Values are
 * always deep-copied (owned strings) rather than reference-counted --
 * simpler and correct, at some performance cost that doesn't matter for
 * a shell-utility-scale interpreter.
 *
 * Number formatting matches real awk's behavior (verified against
 * BusyBox awk): integral values print as plain integers regardless of
 * CONVFMT/OFMT (e.g. 1000000 -> "1000000", not "1e+06"), everything
 * else goes through the %.6g-style format string.
 */

#include "awk_value.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

AwkValue awkValUninit(void) {
    AwkValue v;
    v.kind = AWK_V_UNINIT;
    v.num = 0.0;
    v.str = NULL;
    return v;
}

AwkValue awkValNum(double d) {
    AwkValue v;
    v.kind = AWK_V_NUM;
    v.num = d;
    v.str = NULL;
    return v;
}

AwkValue awkValStr(const char *s) {
    AwkValue v;
    v.kind = AWK_V_STR;
    v.num = 0.0;
    v.str = strdup(s ? s : "");
    return v;
}

bool awkLooksNumeric(const char *s, double *out) {
    if (!s) return false;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return false;
    const char *start = s;
    char *end = NULL;
    double d = strtod(start, &end);
    if (end == start) return false;
    while (isspace((unsigned char)*end)) end++;
    if (*end != '\0') return false;
    if (out) *out = d;
    return true;
}

AwkValue awkValStrNum(const char *s) {
    AwkValue v;
    double d;
    if (awkLooksNumeric(s, &d)) {
        v.kind = AWK_V_STRNUM;
        v.num = d;
    } else {
        v.kind = AWK_V_STRNUM; /* still tagged strnum-origin, but not numeric-context */
        v.num = 0.0;
    }
    v.str = strdup(s ? s : "");
    /* Distinguish "numeric-looking strnum" from "non-numeric strnum" by
     * re-checking in awkIsNumericCtx via awkLooksNumeric again (cheap
     * enough, avoids a separate bool field). */
    return v;
}

AwkValue awkValCopy(const AwkValue *v) {
    AwkValue r = *v;
    r.str = v->str ? strdup(v->str) : NULL;
    return r;
}

void awkValFree(AwkValue *v) {
    if (v && v->str) {
        free(v->str);
        v->str = NULL;
    }
}

bool awkIsNumericCtx(const AwkValue *v) {
    if (v->kind == AWK_V_UNINIT || v->kind == AWK_V_NUM) return true;
    if (v->kind == AWK_V_STRNUM) {
        double d;
        return awkLooksNumeric(v->str, &d);
    }
    return false;
}

bool awkIsTrue(const AwkValue *v) {
    switch (v->kind) {
        case AWK_V_UNINIT: return false;
        case AWK_V_NUM: return v->num != 0.0;
        case AWK_V_STRNUM: {
            double d;
            if (awkLooksNumeric(v->str, &d)) return d != 0.0;
            return v->str && v->str[0] != '\0';
        }
        case AWK_V_STR:
            return v->str && v->str[0] != '\0';
    }
    return false;
}

double awkToNum(const AwkValue *v) {
    switch (v->kind) {
        case AWK_V_UNINIT: return 0.0;
        case AWK_V_NUM: return v->num;
        case AWK_V_STRNUM: {
            double d;
            if (awkLooksNumeric(v->str, &d)) return d;
            /* fall through to prefix parse below */
        }
        /* fallthrough */
        case AWK_V_STR: {
            if (!v->str) return 0.0;
            const char *s = v->str;
            while (isspace((unsigned char)*s)) s++;
            char *end = NULL;
            double d = strtod(s, &end);
            if (end == s) return 0.0;
            return d;
        }
    }
    return 0.0;
}

char *awkFormatNum(double d, const char *fmt) {
    char buf[512];
    if (isnan(d)) { return strdup("nan"); }
    if (isinf(d)) { return strdup(d < 0 ? "-inf" : "inf"); }
    /* Check the magnitude bound FIRST: casting a double outside long
     * long's range (e.g. 1e20) to (long long) is undefined behavior in
     * C, caught by UBSan when this was `d == (double)(long long)d &&
     * fabs(d) < 1e18` -- && evaluates its left side first, which did
     * the unsafe cast before the guard ever ran. */
    if (fabs(d) < 1e18 && d == (double)(long long)d) {
        snprintf(buf, sizeof(buf), "%lld", (long long)d);
        return strdup(buf);
    }
    snprintf(buf, sizeof(buf), fmt && *fmt ? fmt : "%.6g", d);
    return strdup(buf);
}

char *awkToStrFmt(const AwkValue *v, const char *fmt) {
    switch (v->kind) {
        case AWK_V_UNINIT: return strdup("");
        case AWK_V_NUM: return awkFormatNum(v->num, fmt);
        case AWK_V_STR:
        case AWK_V_STRNUM:
            return strdup(v->str ? v->str : "");
    }
    return strdup("");
}

int awkCompare(const AwkValue *a, const AwkValue *b, const char *convfmt) {
    if (awkIsNumericCtx(a) && awkIsNumericCtx(b)) {
        double da = awkToNum(a), db = awkToNum(b);
        if (da < db) return -1;
        if (da > db) return 1;
        return 0;
    }
    char *sa = awkToStrFmt(a, convfmt);
    char *sb = awkToStrFmt(b, convfmt);
    int r = strcmp(sa, sb);
    free(sa);
    free(sb);
    return (r < 0) ? -1 : (r > 0 ? 1 : 0);
}
