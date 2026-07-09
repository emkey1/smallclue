#ifndef SMALLCLUE_AWK_LEXER_H
#define SMALLCLUE_AWK_LEXER_H

#include <stddef.h>

typedef enum {
    AWK_TOK_EOF = 0,
    AWK_TOK_NEWLINE,     /* significant statement terminator */
    AWK_TOK_NUMBER,
    AWK_TOK_STRING,
    AWK_TOK_ERE,         /* /regex/ literal */
    AWK_TOK_FUNC_NAME,   /* identifier immediately followed by '(' (no space) */
    AWK_TOK_NAME,        /* plain identifier */
    AWK_TOK_BUILTIN_FUNC,/* length, substr, split, sub, gsub, ... */
    AWK_TOK_GETLINE,
    AWK_TOK_BEGIN,
    AWK_TOK_END,
    AWK_TOK_FUNCTION,
    AWK_TOK_IF,
    AWK_TOK_ELSE,
    AWK_TOK_WHILE,
    AWK_TOK_FOR,
    AWK_TOK_DO,
    AWK_TOK_BREAK,
    AWK_TOK_CONTINUE,
    AWK_TOK_NEXT,
    AWK_TOK_NEXTFILE,
    AWK_TOK_EXIT,
    AWK_TOK_RETURN,
    AWK_TOK_DELETE,
    AWK_TOK_IN,
    AWK_TOK_PRINT,
    AWK_TOK_PRINTF,
    /* punctuation/operators */
    AWK_TOK_LBRACE, AWK_TOK_RBRACE,
    AWK_TOK_LPAREN, AWK_TOK_RPAREN,
    AWK_TOK_LBRACKET, AWK_TOK_RBRACKET,
    AWK_TOK_SEMI, AWK_TOK_COMMA,
    AWK_TOK_DOLLAR,
    AWK_TOK_ASSIGN, AWK_TOK_ADD_ASSIGN, AWK_TOK_SUB_ASSIGN,
    AWK_TOK_MUL_ASSIGN, AWK_TOK_DIV_ASSIGN, AWK_TOK_MOD_ASSIGN, AWK_TOK_POW_ASSIGN,
    AWK_TOK_OROR, AWK_TOK_ANDAND, AWK_TOK_NOT,
    AWK_TOK_LT, AWK_TOK_LE, AWK_TOK_GT, AWK_TOK_GE, AWK_TOK_EQ, AWK_TOK_NE,
    AWK_TOK_MATCH, AWK_TOK_NOMATCH,
    AWK_TOK_PLUS, AWK_TOK_MINUS, AWK_TOK_STAR, AWK_TOK_SLASH, AWK_TOK_PERCENT, AWK_TOK_CARET,
    AWK_TOK_INCR, AWK_TOK_DECR,
    AWK_TOK_QUESTION, AWK_TOK_COLON,
    AWK_TOK_APPEND,      /* >> */
    AWK_TOK_PIPE,        /* | */
} AwkTokType;

typedef struct {
    AwkTokType type;
    char *text;      /* owned copy: identifier name, string contents (unescaped), or regex source */
    double num;      /* valid when type == AWK_TOK_NUMBER */
    int line;
} AwkToken;

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
    int line;
    AwkTokType lastSignificant; /* for newline-suppression rules */
    int parenDepth;
    int bracketDepth;
    /* Set true right after lexing a NAME/FUNC_NAME/')'/']'/'$'/NUMBER/STRING,
     * so that a following '/' is division, not the start of a regex. */
    int prevAllowsDivision;
} AwkLexer;

void awkLexerInit(AwkLexer *lx, const char *src);
/* Returns the next token. Caller does not own token.text across calls
 * unless it copies it (strdup) -- the parser copies fields it needs into
 * AST nodes immediately. */
AwkToken awkLexerNext(AwkLexer *lx);
void awkTokenFree(AwkToken *tok);

#endif /* SMALLCLUE_AWK_LEXER_H */
