/*
 * AWK lexer. Handles the POSIX awk newline-significance rules (a newline
 * is a statement terminator except right after '{', ',', '&&', '||',
 * 'do', 'else', '?', ':', or while inside unmatched '(' / '['), string/
 * ERE literal scanning with escapes, and the FUNC_NAME-vs-NAME
 * distinction (identifier immediately followed by '(' with no
 * whitespace is a function call name).
 */

#include "awk_lexer.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    AwkTokType type;
} AwkKeyword;

static const AwkKeyword kAwkKeywords[] = {
    {"BEGIN", AWK_TOK_BEGIN}, {"END", AWK_TOK_END},
    {"function", AWK_TOK_FUNCTION}, {"func", AWK_TOK_FUNCTION},
    {"if", AWK_TOK_IF}, {"else", AWK_TOK_ELSE},
    {"while", AWK_TOK_WHILE}, {"for", AWK_TOK_FOR}, {"do", AWK_TOK_DO},
    {"break", AWK_TOK_BREAK}, {"continue", AWK_TOK_CONTINUE},
    {"next", AWK_TOK_NEXT}, {"nextfile", AWK_TOK_NEXTFILE},
    {"exit", AWK_TOK_EXIT}, {"return", AWK_TOK_RETURN},
    {"delete", AWK_TOK_DELETE}, {"in", AWK_TOK_IN},
    {"getline", AWK_TOK_GETLINE},
    {"print", AWK_TOK_PRINT}, {"printf", AWK_TOK_PRINTF},
    {NULL, 0}
};

static const char *kAwkBuiltins[] = {
    "length", "substr", "index", "split", "sub", "gsub", "match",
    "sprintf", "sin", "cos", "atan2", "exp", "log", "sqrt", "int",
    "rand", "srand", "tolower", "toupper", "system", "close", "fflush",
    NULL
};

void awkLexerInit(AwkLexer *lx, const char *src) {
    lx->src = src;
    lx->pos = 0;
    lx->len = strlen(src);
    lx->line = 1;
    lx->lastSignificant = AWK_TOK_NEWLINE; /* start-of-program: newline suppressed */
    lx->parenDepth = 0;
    lx->bracketDepth = 0;
    lx->prevAllowsDivision = 0;
}

void awkTokenFree(AwkToken *tok) {
    if (tok && tok->text) {
        free(tok->text);
        tok->text = NULL;
    }
}

static int awkNewlineSuppressed(AwkLexer *lx) {
    if (lx->parenDepth > 0 || lx->bracketDepth > 0) return 1;
    switch (lx->lastSignificant) {
        case AWK_TOK_LBRACE:
        case AWK_TOK_COMMA:
        case AWK_TOK_ANDAND:
        case AWK_TOK_OROR:
        case AWK_TOK_DO:
        case AWK_TOK_ELSE:
        case AWK_TOK_QUESTION:
        case AWK_TOK_COLON:
        case AWK_TOK_NEWLINE:
        case AWK_TOK_SEMI:
            return 1;
        default:
            return 0;
    }
}

static char peekc(AwkLexer *lx, size_t ahead) {
    size_t p = lx->pos + ahead;
    return p < lx->len ? lx->src[p] : '\0';
}

static void appendChar(char **buf, size_t *len, size_t *cap, char c) {
    if (*len + 1 >= *cap) {
        *cap = *cap ? *cap * 2 : 32;
        *buf = (char *)realloc(*buf, *cap);
    }
    (*buf)[(*len)++] = c;
    (*buf)[*len] = '\0';
}

static AwkTokType awkLookupKeyword(const char *name) {
    for (int i = 0; kAwkKeywords[i].name; ++i) {
        if (strcmp(kAwkKeywords[i].name, name) == 0) return kAwkKeywords[i].type;
    }
    return AWK_TOK_NAME;
}

static int awkIsBuiltinName(const char *name) {
    for (int i = 0; kAwkBuiltins[i]; ++i) {
        if (strcmp(kAwkBuiltins[i], name) == 0) return 1;
    }
    return 0;
}

static void awkSetSignificant(AwkLexer *lx, AwkTokType t, int allowsDivision) {
    lx->lastSignificant = t;
    lx->prevAllowsDivision = allowsDivision;
}

AwkToken awkLexerNext(AwkLexer *lx) {
    AwkToken tok;
    memset(&tok, 0, sizeof(tok));

    int sawSignificantNewline = 0;
    for (;;) {
        char c = peekc(lx, 0);
        if (c == '\0') break;
        if (c == '\\' && peekc(lx, 1) == '\n') {
            lx->pos += 2;
            lx->line++;
            continue;
        }
        if (c == '\\' && peekc(lx, 1) == '\r' && peekc(lx, 2) == '\n') {
            lx->pos += 3;
            lx->line++;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            lx->pos++;
            continue;
        }
        if (c == '#') {
            while (peekc(lx, 0) != '\0' && peekc(lx, 0) != '\n') lx->pos++;
            continue;
        }
        if (c == '\n') {
            if (!sawSignificantNewline && !awkNewlineSuppressed(lx)) {
                sawSignificantNewline = 1;
            }
            lx->pos++;
            lx->line++;
            continue;
        }
        break;
    }

    if (sawSignificantNewline) {
        tok.type = AWK_TOK_NEWLINE;
        tok.line = lx->line;
        awkSetSignificant(lx, AWK_TOK_NEWLINE, 0);
        return tok;
    }

    tok.line = lx->line;
    char c = peekc(lx, 0);
    if (c == '\0') {
        tok.type = AWK_TOK_EOF;
        return tok;
    }

    /* Identifiers / keywords / builtins */
    if (isalpha((unsigned char)c) || c == '_') {
        size_t start = lx->pos;
        while (isalnum((unsigned char)peekc(lx, 0)) || peekc(lx, 0) == '_') lx->pos++;
        size_t idLen = lx->pos - start;
        char *name = (char *)malloc(idLen + 1);
        memcpy(name, lx->src + start, idLen);
        name[idLen] = '\0';

        AwkTokType kw = awkLookupKeyword(name);
        if (kw != AWK_TOK_NAME) {
            free(name);
            tok.type = kw;
            awkSetSignificant(lx, kw, kw == AWK_TOK_GETLINE ? 0 : 0);
            return tok;
        }
        if (awkIsBuiltinName(name)) {
            tok.type = AWK_TOK_BUILTIN_FUNC;
            tok.text = name;
            awkSetSignificant(lx, AWK_TOK_BUILTIN_FUNC, 0);
            return tok;
        }
        if (peekc(lx, 0) == '(') {
            tok.type = AWK_TOK_FUNC_NAME;
        } else {
            tok.type = AWK_TOK_NAME;
        }
        tok.text = name;
        awkSetSignificant(lx, tok.type, 1);
        return tok;
    }

    /* Numbers */
    if (isdigit((unsigned char)c) || (c == '.' && isdigit((unsigned char)peekc(lx, 1)))) {
        size_t start = lx->pos;
        if (c == '0' && (peekc(lx, 1) == 'x' || peekc(lx, 1) == 'X')) {
            lx->pos += 2;
            while (isxdigit((unsigned char)peekc(lx, 0))) lx->pos++;
        } else {
            while (isdigit((unsigned char)peekc(lx, 0))) lx->pos++;
            if (peekc(lx, 0) == '.') {
                lx->pos++;
                while (isdigit((unsigned char)peekc(lx, 0))) lx->pos++;
            }
            if (peekc(lx, 0) == 'e' || peekc(lx, 0) == 'E') {
                size_t save = lx->pos;
                lx->pos++;
                if (peekc(lx, 0) == '+' || peekc(lx, 0) == '-') lx->pos++;
                if (isdigit((unsigned char)peekc(lx, 0))) {
                    while (isdigit((unsigned char)peekc(lx, 0))) lx->pos++;
                } else {
                    lx->pos = save;
                }
            }
        }
        size_t numLen = lx->pos - start;
        char *numStr = (char *)malloc(numLen + 1);
        memcpy(numStr, lx->src + start, numLen);
        numStr[numLen] = '\0';
        tok.type = AWK_TOK_NUMBER;
        tok.num = strtod(numStr, NULL);
        free(numStr);
        awkSetSignificant(lx, AWK_TOK_NUMBER, 1);
        return tok;
    }

    /* Strings */
    if (c == '"') {
        lx->pos++;
        char *buf = NULL;
        size_t len = 0, cap = 0;
        while (peekc(lx, 0) != '\0' && peekc(lx, 0) != '"') {
            char ch = peekc(lx, 0);
            if (ch == '\\') {
                char esc = peekc(lx, 1);
                lx->pos += 2;
                switch (esc) {
                    case 'n': appendChar(&buf, &len, &cap, '\n'); break;
                    case 't': appendChar(&buf, &len, &cap, '\t'); break;
                    case 'r': appendChar(&buf, &len, &cap, '\r'); break;
                    case '\\': appendChar(&buf, &len, &cap, '\\'); break;
                    case '"': appendChar(&buf, &len, &cap, '"'); break;
                    case '/': appendChar(&buf, &len, &cap, '/'); break;
                    case 'a': appendChar(&buf, &len, &cap, '\a'); break;
                    case 'b': appendChar(&buf, &len, &cap, '\b'); break;
                    case 'f': appendChar(&buf, &len, &cap, '\f'); break;
                    case 'v': appendChar(&buf, &len, &cap, '\v'); break;
                    default:
                        if (esc >= '0' && esc <= '7') {
                            int val = esc - '0';
                            for (int i = 0; i < 2 && peekc(lx, 0) >= '0' && peekc(lx, 0) <= '7'; ++i) {
                                val = val * 8 + (peekc(lx, 0) - '0');
                                lx->pos++;
                            }
                            appendChar(&buf, &len, &cap, (char)val);
                        } else {
                            appendChar(&buf, &len, &cap, '\\');
                            appendChar(&buf, &len, &cap, esc);
                        }
                        break;
                }
            } else {
                appendChar(&buf, &len, &cap, ch);
                lx->pos++;
            }
        }
        if (peekc(lx, 0) == '"') lx->pos++;
        tok.type = AWK_TOK_STRING;
        tok.text = buf ? buf : strdup("");
        awkSetSignificant(lx, AWK_TOK_STRING, 1);
        return tok;
    }

    /* Regex literal vs division: only start a regex when the previous
     * token can't end an expression (prevAllowsDivision false). */
    if (c == '/' && !lx->prevAllowsDivision) {
        lx->pos++;
        char *buf = NULL;
        size_t len = 0, cap = 0;
        int inBracket = 0;
        while (peekc(lx, 0) != '\0') {
            char ch = peekc(lx, 0);
            if (ch == '\\') {
                appendChar(&buf, &len, &cap, ch);
                lx->pos++;
                if (peekc(lx, 0) != '\0') {
                    appendChar(&buf, &len, &cap, peekc(lx, 0));
                    lx->pos++;
                }
                continue;
            }
            if (ch == '[' && !inBracket) {
                inBracket = 1;
                appendChar(&buf, &len, &cap, ch);
                lx->pos++;
                if (peekc(lx, 0) == '^') { appendChar(&buf, &len, &cap, '^'); lx->pos++; }
                if (peekc(lx, 0) == ']') { appendChar(&buf, &len, &cap, ']'); lx->pos++; }
                continue;
            }
            if (ch == ']' && inBracket) {
                inBracket = 0;
                appendChar(&buf, &len, &cap, ch);
                lx->pos++;
                continue;
            }
            if (ch == '/' && !inBracket) break;
            if (ch == '\n') break; /* unterminated, bail */
            appendChar(&buf, &len, &cap, ch);
            lx->pos++;
        }
        if (peekc(lx, 0) == '/') lx->pos++;
        tok.type = AWK_TOK_ERE;
        tok.text = buf ? buf : strdup("");
        awkSetSignificant(lx, AWK_TOK_ERE, 1);
        return tok;
    }

    /* Two/three-char operators */
    char c1 = peekc(lx, 1);
    #define ADV(n) (lx->pos += (n))
    switch (c) {
        case '{': ADV(1); tok.type = AWK_TOK_LBRACE; awkSetSignificant(lx, tok.type, 0); return tok;
        case '}': ADV(1); tok.type = AWK_TOK_RBRACE; awkSetSignificant(lx, tok.type, 0); return tok;
        case '(': ADV(1); lx->parenDepth++; tok.type = AWK_TOK_LPAREN; awkSetSignificant(lx, tok.type, 0); return tok;
        case ')': ADV(1); if (lx->parenDepth > 0) lx->parenDepth--; tok.type = AWK_TOK_RPAREN; awkSetSignificant(lx, tok.type, 1); return tok;
        case '[': ADV(1); lx->bracketDepth++; tok.type = AWK_TOK_LBRACKET; awkSetSignificant(lx, tok.type, 0); return tok;
        case ']': ADV(1); if (lx->bracketDepth > 0) lx->bracketDepth--; tok.type = AWK_TOK_RBRACKET; awkSetSignificant(lx, tok.type, 1); return tok;
        case ';': ADV(1); tok.type = AWK_TOK_SEMI; awkSetSignificant(lx, tok.type, 0); return tok;
        case ',': ADV(1); tok.type = AWK_TOK_COMMA; awkSetSignificant(lx, tok.type, 0); return tok;
        case '$': ADV(1); tok.type = AWK_TOK_DOLLAR; awkSetSignificant(lx, tok.type, 0); return tok;
        case '?': ADV(1); tok.type = AWK_TOK_QUESTION; awkSetSignificant(lx, tok.type, 0); return tok;
        case ':': ADV(1); tok.type = AWK_TOK_COLON; awkSetSignificant(lx, tok.type, 0); return tok;
        case '~': ADV(1); tok.type = AWK_TOK_MATCH; awkSetSignificant(lx, tok.type, 0); return tok;
        case '^':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_POW_ASSIGN; } else { ADV(1); tok.type = AWK_TOK_CARET; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '+':
            if (c1 == '+') { ADV(2); tok.type = AWK_TOK_INCR; awkSetSignificant(lx, tok.type, 1); }
            else if (c1 == '=') { ADV(2); tok.type = AWK_TOK_ADD_ASSIGN; awkSetSignificant(lx, tok.type, 0); }
            else { ADV(1); tok.type = AWK_TOK_PLUS; awkSetSignificant(lx, tok.type, 0); }
            return tok;
        case '-':
            if (c1 == '-') { ADV(2); tok.type = AWK_TOK_DECR; awkSetSignificant(lx, tok.type, 1); }
            else if (c1 == '=') { ADV(2); tok.type = AWK_TOK_SUB_ASSIGN; awkSetSignificant(lx, tok.type, 0); }
            else { ADV(1); tok.type = AWK_TOK_MINUS; awkSetSignificant(lx, tok.type, 0); }
            return tok;
        case '*':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_MUL_ASSIGN; } else { ADV(1); tok.type = AWK_TOK_STAR; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '/':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_DIV_ASSIGN; } else { ADV(1); tok.type = AWK_TOK_SLASH; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '%':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_MOD_ASSIGN; } else { ADV(1); tok.type = AWK_TOK_PERCENT; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '=':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_EQ; } else { ADV(1); tok.type = AWK_TOK_ASSIGN; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '<':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_LE; } else { ADV(1); tok.type = AWK_TOK_LT; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '>':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_GE; }
            else if (c1 == '>') { ADV(2); tok.type = AWK_TOK_APPEND; }
            else { ADV(1); tok.type = AWK_TOK_GT; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '!':
            if (c1 == '=') { ADV(2); tok.type = AWK_TOK_NE; }
            else if (c1 == '~') { ADV(2); tok.type = AWK_TOK_NOMATCH; }
            else { ADV(1); tok.type = AWK_TOK_NOT; }
            awkSetSignificant(lx, tok.type, 0);
            return tok;
        case '&':
            if (c1 == '&') { ADV(2); tok.type = AWK_TOK_ANDAND; awkSetSignificant(lx, tok.type, 0); return tok; }
            break;
        case '|':
            if (c1 == '|') { ADV(2); tok.type = AWK_TOK_OROR; awkSetSignificant(lx, tok.type, 0); return tok; }
            ADV(1); tok.type = AWK_TOK_PIPE; awkSetSignificant(lx, tok.type, 0); return tok;
        default:
            break;
    }
    #undef ADV

    /* Unrecognized character: skip it to avoid an infinite loop. */
    lx->pos++;
    tok.type = AWK_TOK_EOF;
    return tok;
}
