#ifndef SMALLCLUE_AWK_VALUE_H
#define SMALLCLUE_AWK_VALUE_H

#include <stdbool.h>

typedef enum { AWK_V_UNINIT, AWK_V_NUM, AWK_V_STR, AWK_V_STRNUM } AwkVKind;

typedef struct {
    AwkVKind kind;
    double num;   /* valid for NUM/STRNUM */
    char *str;    /* owned; valid for STR/STRNUM */
} AwkValue;

AwkValue awkValUninit(void);
AwkValue awkValNum(double d);
AwkValue awkValStr(const char *s);      /* pure string, never numeric-context */
AwkValue awkValStrNum(const char *s);   /* from input: numeric-context if it looks like a number */
AwkValue awkValCopy(const AwkValue *v);
void awkValFree(AwkValue *v);

bool awkLooksNumeric(const char *s, double *out);

/* True if this value participates in numeric comparisons (uninitialized,
 * a real number, or a strnum that looked numeric). */
bool awkIsNumericCtx(const AwkValue *v);
bool awkIsTrue(const AwkValue *v);

double awkToNum(const AwkValue *v);
/* Always returns a freshly malloc'd string; caller frees. `fmt` is
 * CONVFMT or OFMT (%.6g-style); ignored for values that print as a
 * plain integer (POSIX: %d-like output for integral values). */
char *awkToStrFmt(const AwkValue *v, const char *fmt);

/* -1/0/1, using POSIX comparison rules (numeric if both sides are
 * numeric-context, string compare otherwise). */
int awkCompare(const AwkValue *a, const AwkValue *b, const char *convfmt);

/* Formats a double the way awk print/OFMT would (integral -> %.0f style,
 * else the given fmt). Always a fresh malloc'd string. */
char *awkFormatNum(double d, const char *fmt);

#endif /* SMALLCLUE_AWK_VALUE_H */
