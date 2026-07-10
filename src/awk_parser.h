#ifndef SMALLCLUE_AWK_PARSER_H
#define SMALLCLUE_AWK_PARSER_H

#include "awk_lexer.h"
#include <stdbool.h>

typedef enum {
    AWK_E_NUM, AWK_E_STR, AWK_E_REGEX, AWK_E_VAR, AWK_E_FIELD, AWK_E_ARRAYREF,
    AWK_E_ASSIGN, AWK_E_TERNARY, AWK_E_OR, AWK_E_AND, AWK_E_IN, AWK_E_MATCH,
    AWK_E_CMP, AWK_E_CONCAT, AWK_E_BINOP, AWK_E_UNARY,
    AWK_E_PREINCR, AWK_E_PREDECR, AWK_E_POSTINCR, AWK_E_POSTDECR,
    AWK_E_CALL, AWK_E_GETLINE, AWK_E_GROUP,

    AWK_S_EXPR, AWK_S_PRINT, AWK_S_PRINTF, AWK_S_IF, AWK_S_WHILE, AWK_S_DOWHILE,
    AWK_S_FOR, AWK_S_FORIN, AWK_S_BREAK, AWK_S_CONTINUE, AWK_S_NEXT, AWK_S_NEXTFILE,
    AWK_S_EXIT, AWK_S_RETURN, AWK_S_DELETE, AWK_S_DELETE_ALL, AWK_S_BLOCK,

    AWK_ITEM_RULE, AWK_ITEM_FUNC,
} AwkNodeKind;

typedef enum {
    AWK_PAT_BEGIN, AWK_PAT_END, AWK_PAT_ALWAYS, AWK_PAT_EXPR, AWK_PAT_RANGE
} AwkPatternKind;

/* getline source kind */
typedef enum { AWK_GL_NONE, AWK_GL_FILE, AWK_GL_CMD } AwkGetlineSrc;

/* print/printf redirection kind */
typedef enum { AWK_REDIR_NONE, AWK_REDIR_FILE, AWK_REDIR_APPEND, AWK_REDIR_PIPE } AwkRedirKind;

typedef struct AwkNode {
    AwkNodeKind kind;
    int op;              /* token type for BINOP/CMP/ASSIGN op-kind/UNARY */
    double num;           /* AWK_E_NUM */
    char *str;             /* literal text / var name / array name / call name */
    char *str2;             /* secondary name (for-in array name, etc.) */
    struct AwkNode *a, *b, *c; /* generic children */
    struct AwkNode **list;      /* generic child list (args, subscripts, stmts) */
    int listCount;
    bool isBuiltin;        /* AWK_E_CALL: builtin vs user function */
    AwkGetlineSrc glSrc;
    AwkRedirKind redir;
    AwkPatternKind patKind; /* AWK_ITEM_RULE */
    char **params;          /* AWK_ITEM_FUNC parameter names */
    int paramCount;
    int line;
} AwkNode;

typedef struct {
    AwkNode **items; /* top-level rules and function defs, in source order */
    int itemCount;
} AwkProgram;

/* Parses the full program text. On a syntax error, prints a message to
 * stderr (prefixed "awk: syntax error") and returns NULL. */
AwkProgram *awkParseProgram(const char *src);

AwkNode *awkNewNode(AwkNodeKind kind);

#endif /* SMALLCLUE_AWK_PARSER_H */
