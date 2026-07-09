/*
 * Recursive-descent parser for the AWK grammar (POSIX awk / BusyBox awk
 * feature surface). Produces a flat-struct AST (AwkNode) that the
 * interpreter walks directly -- no separate "compile" step.
 *
 * Notable implementation choices:
 * - The lexer already resolves most of awk's newline-significance rules
 *   (see awk_lexer.c); this parser just consumes AWK_TOK_NEWLINE as a
 *   statement terminator equivalent to ';'.
 * - `for (NAME in NAME)` vs a normal C-style for-loop is disambiguated
 *   with a throwaway clone of the lexer state (AwkLexer has no owned
 *   pointers, so cloning it by value is a safe, cheap 1-token lookahead
 *   with no backtracking needed on the real parser state).
 * - print/printf's argument list is parsed with a "printCtx" flag that
 *   suppresses top-level '>' (comparison) and '| getline' so the
 *   trailing output-redirection syntax (`> file`, `>> file`, `| cmd`)
 *   can be recognized unambiguously; parentheses reset the flag.
 */

#include "awk_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    AwkLexer lx;
    AwkToken cur;
    bool printCtx;
    bool error;
} AwkParser;

AwkNode *awkNewNode(AwkNodeKind kind) {
    AwkNode *n = (AwkNode *)calloc(1, sizeof(AwkNode));
    n->kind = kind;
    return n;
}

static void awkParserAdvance(AwkParser *p) {
    awkTokenFree(&p->cur);
    p->cur = awkLexerNext(&p->lx);
}

static void awkSyntaxError(AwkParser *p, const char *msg) {
    if (!p->error) {
        fprintf(stderr, "awk: syntax error at line %d: %s\n", p->cur.line, msg);
    }
    p->error = true;
}

static bool awkCheck(AwkParser *p, AwkTokType t) { return p->cur.type == t; }

static bool awkAccept(AwkParser *p, AwkTokType t) {
    if (p->cur.type == t) { awkParserAdvance(p); return true; }
    return false;
}

static void awkExpect(AwkParser *p, AwkTokType t, const char *what) {
    if (p->cur.type != t) {
        char buf[128];
        snprintf(buf, sizeof(buf), "expected %s", what);
        awkSyntaxError(p, buf);
        return;
    }
    awkParserAdvance(p);
}

static void awkSkipTerms(AwkParser *p) {
    while (awkCheck(p, AWK_TOK_NEWLINE) || awkCheck(p, AWK_TOK_SEMI)) awkParserAdvance(p);
}

static void awkSkipOptNewlines(AwkParser *p) {
    while (awkCheck(p, AWK_TOK_NEWLINE)) awkParserAdvance(p);
}

/* Forward declarations */
static AwkNode *parseExpr(AwkParser *p);
static AwkNode *parseTernary(AwkParser *p);
static AwkNode *parseStatement(AwkParser *p);
static AwkNode *parseSimpleStatement(AwkParser *p);
static AwkNode **parseStatementListUntil(AwkParser *p, int *count, AwkTokType stopTok);

/* ---- Expression grammar ---- */

static AwkNode *parsePrimary(AwkParser *p);

static bool awkNextIsRegexLikeUnaryStart(AwkParser *p) {
    switch (p->cur.type) {
        case AWK_TOK_NUMBER: case AWK_TOK_STRING: case AWK_TOK_ERE:
        case AWK_TOK_NAME: case AWK_TOK_FUNC_NAME: case AWK_TOK_BUILTIN_FUNC:
        case AWK_TOK_DOLLAR: case AWK_TOK_LPAREN: case AWK_TOK_NOT:
        case AWK_TOK_MINUS: case AWK_TOK_PLUS: case AWK_TOK_INCR: case AWK_TOK_DECR:
        case AWK_TOK_GETLINE:
            return true;
        default:
            return false;
    }
}

/* lvalue forms: NAME, NAME[subs], $expr */
static AwkNode *parseLvalueForGetline(AwkParser *p) {
    if (awkCheck(p, AWK_TOK_DOLLAR)) {
        awkParserAdvance(p);
        AwkNode *n = awkNewNode(AWK_E_FIELD);
        n->a = parsePrimary(p);
        return n;
    }
    if (awkCheck(p, AWK_TOK_NAME)) {
        char *name = strdup(p->cur.text);
        awkParserAdvance(p);
        if (awkAccept(p, AWK_TOK_LBRACKET)) {
            AwkNode *n = awkNewNode(AWK_E_ARRAYREF);
            n->str = name;
            int cnt = 0;
            AwkNode **subs = NULL;
            for (;;) {
                AwkNode *idx = parseExpr(p);
                subs = (AwkNode **)realloc(subs, sizeof(AwkNode *) * (size_t)(cnt + 1));
                subs[cnt++] = idx;
                if (!awkAccept(p, AWK_TOK_COMMA)) break;
            }
            awkExpect(p, AWK_TOK_RBRACKET, "']'");
            n->list = subs;
            n->listCount = cnt;
            return n;
        }
        AwkNode *n = awkNewNode(AWK_E_VAR);
        n->str = name;
        return n;
    }
    return NULL;
}

static AwkNode *parseGetline(AwkParser *p) {
    awkExpect(p, AWK_TOK_GETLINE, "getline");
    AwkNode *n = awkNewNode(AWK_E_GETLINE);
    n->glSrc = AWK_GL_NONE;
    if (awkCheck(p, AWK_TOK_NAME) || awkCheck(p, AWK_TOK_DOLLAR)) {
        n->a = parseLvalueForGetline(p);
    }
    if (awkAccept(p, AWK_TOK_LT)) {
        n->glSrc = AWK_GL_FILE;
        n->b = parseTernary(p);
    }
    return n;
}

static AwkNode *parsePrimary(AwkParser *p) {
    AwkNode *n;
    switch (p->cur.type) {
        case AWK_TOK_NUMBER: {
            n = awkNewNode(AWK_E_NUM);
            n->num = p->cur.num;
            awkParserAdvance(p);
            return n;
        }
        case AWK_TOK_STRING: {
            n = awkNewNode(AWK_E_STR);
            n->str = strdup(p->cur.text);
            awkParserAdvance(p);
            return n;
        }
        case AWK_TOK_ERE: {
            n = awkNewNode(AWK_E_REGEX);
            n->str = strdup(p->cur.text);
            awkParserAdvance(p);
            return n;
        }
        case AWK_TOK_DOLLAR: {
            awkParserAdvance(p);
            n = awkNewNode(AWK_E_FIELD);
            n->a = parsePrimary(p);
            return n;
        }
        case AWK_TOK_INCR: case AWK_TOK_DECR: {
            bool isIncr = (p->cur.type == AWK_TOK_INCR);
            awkParserAdvance(p);
            AwkNode *target = parsePrimary(p);
            n = awkNewNode(isIncr ? AWK_E_PREINCR : AWK_E_PREDECR);
            n->a = target;
            return n;
        }
        case AWK_TOK_NOT: {
            awkParserAdvance(p);
            n = awkNewNode(AWK_E_UNARY);
            n->op = AWK_TOK_NOT;
            n->a = parseTernary(p); /* unary binds loosely enough to cover !a==b as !(a==b)? real awk: ! binds tighter than most; simplify via calling unary-precedence recursively below */
            return n;
        }
        case AWK_TOK_MINUS: case AWK_TOK_PLUS: {
            int op = p->cur.type;
            awkParserAdvance(p);
            n = awkNewNode(AWK_E_UNARY);
            n->op = op;
            n->a = parsePrimary(p);
            return n;
        }
        case AWK_TOK_LPAREN: {
            bool savedCtx = p->printCtx;
            p->printCtx = false;
            awkParserAdvance(p);
            AwkNode *first = parseExpr(p);
            if (awkCheck(p, AWK_TOK_COMMA)) {
                int cnt = 1;
                AwkNode **items = (AwkNode **)malloc(sizeof(AwkNode *));
                items[0] = first;
                while (awkAccept(p, AWK_TOK_COMMA)) {
                    awkSkipOptNewlines(p);
                    AwkNode *e = parseExpr(p);
                    items = (AwkNode **)realloc(items, sizeof(AwkNode *) * (size_t)(cnt + 1));
                    items[cnt++] = e;
                }
                awkExpect(p, AWK_TOK_RPAREN, "')'");
                p->printCtx = savedCtx;
                n = awkNewNode(AWK_E_GROUP);
                n->list = items;
                n->listCount = cnt;
                return n;
            }
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            p->printCtx = savedCtx;
            n = awkNewNode(AWK_E_GROUP);
            n->list = (AwkNode **)malloc(sizeof(AwkNode *));
            n->list[0] = first;
            n->listCount = 1;
            return n;
        }
        case AWK_TOK_GETLINE:
            return parseGetline(p);
        case AWK_TOK_BUILTIN_FUNC: {
            char *name = strdup(p->cur.text);
            awkParserAdvance(p);
            n = awkNewNode(AWK_E_CALL);
            n->str = name;
            n->isBuiltin = true;
            if (awkAccept(p, AWK_TOK_LPAREN)) {
                bool savedCtx = p->printCtx;
                p->printCtx = false;
                awkSkipOptNewlines(p);
                if (!awkCheck(p, AWK_TOK_RPAREN)) {
                    int cnt = 0;
                    AwkNode **args = NULL;
                    for (;;) {
                        AwkNode *a = parseExpr(p);
                        args = (AwkNode **)realloc(args, sizeof(AwkNode *) * (size_t)(cnt + 1));
                        args[cnt++] = a;
                        awkSkipOptNewlines(p);
                        if (!awkAccept(p, AWK_TOK_COMMA)) break;
                        awkSkipOptNewlines(p);
                    }
                    n->list = args;
                    n->listCount = cnt;
                }
                awkExpect(p, AWK_TOK_RPAREN, "')'");
                p->printCtx = savedCtx;
            }
            return n;
        }
        case AWK_TOK_FUNC_NAME: {
            char *name = strdup(p->cur.text);
            awkParserAdvance(p);
            n = awkNewNode(AWK_E_CALL);
            n->str = name;
            n->isBuiltin = false;
            awkExpect(p, AWK_TOK_LPAREN, "'('");
            bool savedCtx = p->printCtx;
            p->printCtx = false;
            awkSkipOptNewlines(p);
            if (!awkCheck(p, AWK_TOK_RPAREN)) {
                int cnt = 0;
                AwkNode **args = NULL;
                for (;;) {
                    AwkNode *a = parseExpr(p);
                    args = (AwkNode **)realloc(args, sizeof(AwkNode *) * (size_t)(cnt + 1));
                    args[cnt++] = a;
                    awkSkipOptNewlines(p);
                    if (!awkAccept(p, AWK_TOK_COMMA)) break;
                    awkSkipOptNewlines(p);
                }
                n->list = args;
                n->listCount = cnt;
            }
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            p->printCtx = savedCtx;
            return n;
        }
        case AWK_TOK_NAME: {
            char *name = strdup(p->cur.text);
            awkParserAdvance(p);
            if (awkAccept(p, AWK_TOK_LBRACKET)) {
                n = awkNewNode(AWK_E_ARRAYREF);
                n->str = name;
                int cnt = 0;
                AwkNode **subs = NULL;
                for (;;) {
                    AwkNode *idx = parseExpr(p);
                    subs = (AwkNode **)realloc(subs, sizeof(AwkNode *) * (size_t)(cnt + 1));
                    subs[cnt++] = idx;
                    if (!awkAccept(p, AWK_TOK_COMMA)) break;
                }
                awkExpect(p, AWK_TOK_RBRACKET, "']'");
                n->list = subs;
                n->listCount = cnt;
                return n;
            }
            n = awkNewNode(AWK_E_VAR);
            n->str = name;
            return n;
        }
        default:
            awkSyntaxError(p, "unexpected token");
            awkParserAdvance(p);
            return awkNewNode(AWK_E_NUM);
    }
}

static AwkNode *parsePostfix(AwkParser *p) {
    AwkNode *n = parsePrimary(p);
    for (;;) {
        if (awkCheck(p, AWK_TOK_INCR) &&
            (n->kind == AWK_E_VAR || n->kind == AWK_E_ARRAYREF || n->kind == AWK_E_FIELD)) {
            awkParserAdvance(p);
            AwkNode *inc = awkNewNode(AWK_E_POSTINCR);
            inc->a = n;
            n = inc;
            continue;
        }
        if (awkCheck(p, AWK_TOK_DECR) &&
            (n->kind == AWK_E_VAR || n->kind == AWK_E_ARRAYREF || n->kind == AWK_E_FIELD)) {
            awkParserAdvance(p);
            AwkNode *dec = awkNewNode(AWK_E_POSTDECR);
            dec->a = n;
            n = dec;
            continue;
        }
        break;
    }
    return n;
}

static AwkNode *parsePower(AwkParser *p) {
    AwkNode *left = parsePostfix(p);
    if (awkAccept(p, AWK_TOK_CARET)) {
        AwkNode *right = parsePower(p); /* right-assoc; also allows unary after ^ e.g. 2^-3 */
        AwkNode *n = awkNewNode(AWK_E_BINOP);
        n->op = AWK_TOK_CARET;
        n->a = left; n->b = right;
        return n;
    }
    return left;
}

static AwkNode *parseUnary(AwkParser *p) {
    /* Handles unary +/-/! at this precedence too, since real awk allows
     * e.g. `-2^2` == -(2^2). parsePrimary already handles a leading
     * unary operator for the common case; this level exists so unary
     * binds looser than '^' but tighter than * / %. */
    return parsePower(p);
}

static AwkNode *parseMultiplicative(AwkParser *p) {
    AwkNode *left = parseUnary(p);
    for (;;) {
        int op = p->cur.type;
        if (op != AWK_TOK_STAR && op != AWK_TOK_SLASH && op != AWK_TOK_PERCENT) break;
        awkParserAdvance(p);
        AwkNode *right = parseUnary(p);
        AwkNode *n = awkNewNode(AWK_E_BINOP);
        n->op = op;
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static AwkNode *parseAdditive(AwkParser *p) {
    AwkNode *left = parseMultiplicative(p);
    for (;;) {
        int op = p->cur.type;
        if (op != AWK_TOK_PLUS && op != AWK_TOK_MINUS) break;
        awkParserAdvance(p);
        AwkNode *right = parseMultiplicative(p);
        AwkNode *n = awkNewNode(AWK_E_BINOP);
        n->op = op;
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static bool awkStartsConcatOperand(AwkParser *p) {
    switch (p->cur.type) {
        case AWK_TOK_NUMBER: case AWK_TOK_STRING: case AWK_TOK_ERE:
        case AWK_TOK_NAME: case AWK_TOK_FUNC_NAME: case AWK_TOK_BUILTIN_FUNC:
        case AWK_TOK_DOLLAR: case AWK_TOK_LPAREN: case AWK_TOK_NOT:
        case AWK_TOK_INCR: case AWK_TOK_DECR:
        case AWK_TOK_MINUS: case AWK_TOK_PLUS:
            return true;
        default:
            return false;
    }
}

static AwkNode *parseConcat(AwkParser *p) {
    AwkNode *left = parseAdditive(p);
    while (awkStartsConcatOperand(p)) {
        AwkNode *right = parseAdditive(p);
        AwkNode *n = awkNewNode(AWK_E_CONCAT);
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static AwkNode *parseRelational(AwkParser *p) {
    AwkNode *left = parseConcat(p);
    int op = p->cur.type;
    bool isRel = (op == AWK_TOK_LT || op == AWK_TOK_LE || op == AWK_TOK_GE ||
                  op == AWK_TOK_NE || op == AWK_TOK_EQ ||
                  (op == AWK_TOK_GT && !p->printCtx));
    if (isRel) {
        awkParserAdvance(p);
        AwkNode *right = parseConcat(p);
        AwkNode *n = awkNewNode(AWK_E_CMP);
        n->op = op;
        n->a = left; n->b = right;
        return n;
    }
    return left;
}

static AwkNode *parsePipeGetline(AwkParser *p) {
    AwkNode *left = parseRelational(p);
    while (!p->printCtx && awkCheck(p, AWK_TOK_PIPE)) {
        /* lookahead: only treat '|' specially if followed by getline */
        AwkLexer probe = p->lx;
        AwkToken t = awkLexerNext(&probe);
        bool isGetline = (t.type == AWK_TOK_GETLINE);
        awkTokenFree(&t);
        if (!isGetline) break;
        awkParserAdvance(p); /* consume '|' */
        AwkNode *gl = parseGetline(p);
        gl->glSrc = AWK_GL_CMD;
        gl->b = left;
        left = gl;
    }
    return left;
}

static AwkNode *parseMatch(AwkParser *p) {
    AwkNode *left = parsePipeGetline(p);
    while (awkCheck(p, AWK_TOK_MATCH) || awkCheck(p, AWK_TOK_NOMATCH)) {
        bool neg = awkCheck(p, AWK_TOK_NOMATCH);
        awkParserAdvance(p);
        AwkNode *right = parsePipeGetline(p);
        AwkNode *n = awkNewNode(AWK_E_MATCH);
        n->op = neg ? 1 : 0;
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static AwkNode *parseIn(AwkParser *p) {
    AwkNode *left = parseMatch(p);
    while (awkCheck(p, AWK_TOK_IN)) {
        awkParserAdvance(p);
        if (!awkCheck(p, AWK_TOK_NAME)) {
            awkSyntaxError(p, "expected array name after 'in'");
            break;
        }
        char *arrName = strdup(p->cur.text);
        awkParserAdvance(p);
        AwkNode *n = awkNewNode(AWK_E_IN);
        n->str = arrName;
        if (left->kind == AWK_E_GROUP && left->listCount > 1) {
            n->list = left->list;
            n->listCount = left->listCount;
        } else {
            n->list = (AwkNode **)malloc(sizeof(AwkNode *));
            n->list[0] = (left->kind == AWK_E_GROUP && left->listCount == 1) ? left->list[0] : left;
            n->listCount = 1;
        }
        left = n;
    }
    return left;
}

static AwkNode *parseAnd(AwkParser *p) {
    AwkNode *left = parseIn(p);
    while (awkCheck(p, AWK_TOK_ANDAND)) {
        awkParserAdvance(p);
        awkSkipOptNewlines(p);
        AwkNode *right = parseIn(p);
        AwkNode *n = awkNewNode(AWK_E_AND);
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static AwkNode *parseOr(AwkParser *p) {
    AwkNode *left = parseAnd(p);
    while (awkCheck(p, AWK_TOK_OROR)) {
        awkParserAdvance(p);
        awkSkipOptNewlines(p);
        AwkNode *right = parseAnd(p);
        AwkNode *n = awkNewNode(AWK_E_OR);
        n->a = left; n->b = right;
        left = n;
    }
    return left;
}

static AwkNode *parseTernary(AwkParser *p) {
    AwkNode *cond = parseOr(p);
    if (awkAccept(p, AWK_TOK_QUESTION)) {
        awkSkipOptNewlines(p);
        AwkNode *thenE = parseTernary(p);
        awkSkipOptNewlines(p);
        awkExpect(p, AWK_TOK_COLON, "':'");
        awkSkipOptNewlines(p);
        AwkNode *elseE = parseTernary(p);
        AwkNode *n = awkNewNode(AWK_E_TERNARY);
        n->a = cond; n->b = thenE; n->c = elseE;
        return n;
    }
    return cond;
}

static bool awkIsLvalue(AwkNode *n) {
    return n->kind == AWK_E_VAR || n->kind == AWK_E_ARRAYREF || n->kind == AWK_E_FIELD;
}

static int awkAssignOpFor(AwkTokType t) {
    switch (t) {
        case AWK_TOK_ASSIGN: return AWK_TOK_ASSIGN;
        case AWK_TOK_ADD_ASSIGN: return AWK_TOK_ADD_ASSIGN;
        case AWK_TOK_SUB_ASSIGN: return AWK_TOK_SUB_ASSIGN;
        case AWK_TOK_MUL_ASSIGN: return AWK_TOK_MUL_ASSIGN;
        case AWK_TOK_DIV_ASSIGN: return AWK_TOK_DIV_ASSIGN;
        case AWK_TOK_MOD_ASSIGN: return AWK_TOK_MOD_ASSIGN;
        case AWK_TOK_POW_ASSIGN: return AWK_TOK_POW_ASSIGN;
        default: return 0;
    }
}

static AwkNode *parseExpr(AwkParser *p) {
    AwkNode *left = parseTernary(p);
    int aop = awkAssignOpFor(p->cur.type);
    if (aop != 0 && awkIsLvalue(left)) {
        awkParserAdvance(p);
        awkSkipOptNewlines(p);
        AwkNode *right = parseExpr(p); /* right-assoc */
        AwkNode *n = awkNewNode(AWK_E_ASSIGN);
        n->op = aop;
        n->a = left; n->b = right;
        return n;
    }
    return left;
}

/* ---- Statement grammar ---- */

static AwkNode **parseExprListPrintCtx(AwkParser *p, int *count) {
    int cnt = 0;
    AwkNode **items = NULL;
    bool savedCtx = p->printCtx;
    p->printCtx = true;
    if (!awkCheck(p, AWK_TOK_GT) && !awkCheck(p, AWK_TOK_APPEND) && !awkCheck(p, AWK_TOK_PIPE) &&
        !awkCheck(p, AWK_TOK_SEMI) && !awkCheck(p, AWK_TOK_NEWLINE) && !awkCheck(p, AWK_TOK_RBRACE) &&
        !awkCheck(p, AWK_TOK_EOF)) {
        for (;;) {
            AwkNode *e = parseTernary(p);
            items = (AwkNode **)realloc(items, sizeof(AwkNode *) * (size_t)(cnt + 1));
            items[cnt++] = e;
            if (!awkAccept(p, AWK_TOK_COMMA)) break;
            awkSkipOptNewlines(p);
        }
    }
    p->printCtx = savedCtx;
    /* print (a,b) idiom: single parenthesized multi-item group unwraps */
    if (cnt == 1 && items[0]->kind == AWK_E_GROUP && items[0]->listCount > 1) {
        AwkNode **unwrapped = items[0]->list;
        int n = items[0]->listCount;
        free(items);
        *count = n;
        return unwrapped;
    }
    *count = cnt;
    return items;
}

static AwkNode *parsePrintLike(AwkParser *p, bool isPrintf) {
    awkParserAdvance(p); /* consume PRINT/PRINTF */
    AwkNode *n = awkNewNode(isPrintf ? AWK_S_PRINTF : AWK_S_PRINT);
    int cnt = 0;
    n->list = parseExprListPrintCtx(p, &cnt);
    n->listCount = cnt;
    if (awkAccept(p, AWK_TOK_GT)) {
        n->redir = AWK_REDIR_FILE;
        n->a = parseTernary(p);
    } else if (awkAccept(p, AWK_TOK_APPEND)) {
        n->redir = AWK_REDIR_APPEND;
        n->a = parseTernary(p);
    } else if (awkAccept(p, AWK_TOK_PIPE)) {
        n->redir = AWK_REDIR_PIPE;
        n->a = parseTernary(p);
    }
    return n;
}

static AwkNode *parseBlock(AwkParser *p) {
    awkExpect(p, AWK_TOK_LBRACE, "'{'");
    int cnt = 0;
    AwkNode **stmts = parseStatementListUntil(p, &cnt, AWK_TOK_RBRACE);
    awkExpect(p, AWK_TOK_RBRACE, "'}'");
    AwkNode *n = awkNewNode(AWK_S_BLOCK);
    n->list = stmts;
    n->listCount = cnt;
    return n;
}

static AwkNode *parseSimpleStatement(AwkParser *p) {
    if (awkCheck(p, AWK_TOK_PRINT)) return parsePrintLike(p, false);
    if (awkCheck(p, AWK_TOK_PRINTF)) return parsePrintLike(p, true);
    if (awkCheck(p, AWK_TOK_DELETE)) {
        awkParserAdvance(p);
        if (!awkCheck(p, AWK_TOK_NAME)) {
            awkSyntaxError(p, "expected array name after delete");
            return awkNewNode(AWK_S_DELETE_ALL);
        }
        char *name = strdup(p->cur.text);
        awkParserAdvance(p);
        if (awkAccept(p, AWK_TOK_LBRACKET)) {
            AwkNode *n = awkNewNode(AWK_S_DELETE);
            n->str = name;
            int cnt = 0;
            AwkNode **subs = NULL;
            for (;;) {
                AwkNode *idx = parseExpr(p);
                subs = (AwkNode **)realloc(subs, sizeof(AwkNode *) * (size_t)(cnt + 1));
                subs[cnt++] = idx;
                if (!awkAccept(p, AWK_TOK_COMMA)) break;
            }
            awkExpect(p, AWK_TOK_RBRACKET, "']'");
            n->list = subs;
            n->listCount = cnt;
            return n;
        }
        /* optional empty () for `delete arr()` some scripts use -- accept if present */
        if (awkAccept(p, AWK_TOK_LPAREN)) {
            awkExpect(p, AWK_TOK_RPAREN, "')'");
        }
        AwkNode *n = awkNewNode(AWK_S_DELETE_ALL);
        n->str = name;
        return n;
    }
    AwkNode *n = awkNewNode(AWK_S_EXPR);
    n->a = parseExpr(p);
    return n;
}

static AwkNode *parseStatement(AwkParser *p) {
    awkSkipOptNewlines(p);
    switch (p->cur.type) {
        case AWK_TOK_LBRACE:
            return parseBlock(p);
        case AWK_TOK_IF: {
            awkParserAdvance(p);
            awkExpect(p, AWK_TOK_LPAREN, "'('");
            AwkNode *cond = parseExpr(p);
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            awkSkipOptNewlines(p);
            AwkNode *thenS = parseStatement(p);
            AwkNode *elseS = NULL;
            /* allow optional terminator(s) before 'else' */
            AwkLexer saveLx = p->lx;
            AwkToken saveCur = p->cur;
            int skipped = 0;
            while (awkCheck(p, AWK_TOK_NEWLINE) || awkCheck(p, AWK_TOK_SEMI)) { awkParserAdvance(p); skipped++; }
            if (awkCheck(p, AWK_TOK_ELSE)) {
                awkParserAdvance(p);
                awkSkipOptNewlines(p);
                elseS = parseStatement(p);
            } else if (skipped > 0) {
                /* not an else; but we already consumed the terminator(s), which is fine
                 * since a terminator was expected there anyway. Nothing to restore. */
                (void)saveLx; (void)saveCur;
            }
            AwkNode *n = awkNewNode(AWK_S_IF);
            n->a = cond; n->b = thenS; n->c = elseS;
            return n;
        }
        case AWK_TOK_WHILE: {
            awkParserAdvance(p);
            awkExpect(p, AWK_TOK_LPAREN, "'('");
            AwkNode *cond = parseExpr(p);
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            awkSkipOptNewlines(p);
            AwkNode *body = parseStatement(p);
            AwkNode *n = awkNewNode(AWK_S_WHILE);
            n->a = cond; n->b = body;
            return n;
        }
        case AWK_TOK_DO: {
            awkParserAdvance(p);
            awkSkipOptNewlines(p);
            AwkNode *body = parseStatement(p);
            awkSkipTerms(p);
            awkExpect(p, AWK_TOK_WHILE, "'while'");
            awkExpect(p, AWK_TOK_LPAREN, "'('");
            AwkNode *cond = parseExpr(p);
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            AwkNode *n = awkNewNode(AWK_S_DOWHILE);
            n->a = cond; n->b = body;
            return n;
        }
        case AWK_TOK_FOR: {
            awkParserAdvance(p);
            awkExpect(p, AWK_TOK_LPAREN, "'('");
            if (awkCheck(p, AWK_TOK_NAME)) {
                AwkLexer probe = p->lx;
                AwkToken t = awkLexerNext(&probe);
                bool isForIn = (t.type == AWK_TOK_IN);
                awkTokenFree(&t);
                if (isForIn) {
                    char *varName = strdup(p->cur.text);
                    awkParserAdvance(p); /* NAME */
                    awkParserAdvance(p); /* in */
                    if (!awkCheck(p, AWK_TOK_NAME)) {
                        awkSyntaxError(p, "expected array name in for-in");
                    }
                    char *arrName = strdup(p->cur.text);
                    awkParserAdvance(p);
                    awkExpect(p, AWK_TOK_RPAREN, "')'");
                    awkSkipOptNewlines(p);
                    AwkNode *body = parseStatement(p);
                    AwkNode *n = awkNewNode(AWK_S_FORIN);
                    n->str = varName;
                    n->str2 = arrName;
                    n->a = body;
                    return n;
                }
            }
            AwkNode *init = NULL, *cond = NULL, *post = NULL;
            if (!awkCheck(p, AWK_TOK_SEMI)) init = parseSimpleStatement(p);
            awkExpect(p, AWK_TOK_SEMI, "';'");
            if (!awkCheck(p, AWK_TOK_SEMI)) cond = parseExpr(p);
            awkExpect(p, AWK_TOK_SEMI, "';'");
            if (!awkCheck(p, AWK_TOK_RPAREN)) post = parseSimpleStatement(p);
            awkExpect(p, AWK_TOK_RPAREN, "')'");
            awkSkipOptNewlines(p);
            AwkNode *body = parseStatement(p);
            AwkNode *n = awkNewNode(AWK_S_FOR);
            n->a = init; n->b = cond; n->c = post;
            n->list = (AwkNode **)malloc(sizeof(AwkNode *));
            n->list[0] = body;
            n->listCount = 1;
            return n;
        }
        case AWK_TOK_BREAK: awkParserAdvance(p); return awkNewNode(AWK_S_BREAK);
        case AWK_TOK_CONTINUE: awkParserAdvance(p); return awkNewNode(AWK_S_CONTINUE);
        case AWK_TOK_NEXT: awkParserAdvance(p); return awkNewNode(AWK_S_NEXT);
        case AWK_TOK_NEXTFILE: awkParserAdvance(p); return awkNewNode(AWK_S_NEXTFILE);
        case AWK_TOK_EXIT: {
            awkParserAdvance(p);
            AwkNode *n = awkNewNode(AWK_S_EXIT);
            if (awkNextIsRegexLikeUnaryStart(p) && !awkCheck(p, AWK_TOK_GETLINE)) n->a = parseExpr(p);
            else if (awkCheck(p, AWK_TOK_GETLINE)) { /* rare, but permit */ }
            return n;
        }
        case AWK_TOK_RETURN: {
            awkParserAdvance(p);
            AwkNode *n = awkNewNode(AWK_S_RETURN);
            if (awkNextIsRegexLikeUnaryStart(p)) n->a = parseExpr(p);
            return n;
        }
        case AWK_TOK_SEMI:
            return awkNewNode(AWK_S_BLOCK); /* empty statement */
        default:
            return parseSimpleStatement(p);
    }
}

static AwkNode **parseStatementListUntil(AwkParser *p, int *count, AwkTokType stopTok) {
    int cnt = 0;
    AwkNode **stmts = NULL;
    awkSkipTerms(p);
    while (!awkCheck(p, stopTok) && !awkCheck(p, AWK_TOK_EOF) && !p->error) {
        AwkNode *s = parseStatement(p);
        stmts = (AwkNode **)realloc(stmts, sizeof(AwkNode *) * (size_t)(cnt + 1));
        stmts[cnt++] = s;
        awkSkipTerms(p);
    }
    *count = cnt;
    return stmts;
}

/* ---- Top-level program ---- */

static AwkNode *parsePattern(AwkParser *p, AwkPatternKind *kindOut) {
    if (awkAccept(p, AWK_TOK_BEGIN)) { *kindOut = AWK_PAT_BEGIN; return NULL; }
    if (awkAccept(p, AWK_TOK_END)) { *kindOut = AWK_PAT_END; return NULL; }
    if (awkCheck(p, AWK_TOK_LBRACE)) { *kindOut = AWK_PAT_ALWAYS; return NULL; }
    AwkNode *e1 = parseExpr(p);
    if (awkAccept(p, AWK_TOK_COMMA)) {
        awkSkipOptNewlines(p);
        AwkNode *e2 = parseExpr(p);
        *kindOut = AWK_PAT_RANGE;
        AwkNode *n = awkNewNode(AWK_ITEM_RULE);
        n->a = e1; n->b = e2;
        return n;
    }
    *kindOut = AWK_PAT_EXPR;
    return e1;
}

static AwkNode *parseFunctionDef(AwkParser *p) {
    awkParserAdvance(p); /* function/func */
    AwkNode *n = awkNewNode(AWK_ITEM_FUNC);
    if (awkCheck(p, AWK_TOK_NAME) || awkCheck(p, AWK_TOK_FUNC_NAME)) {
        n->str = strdup(p->cur.text);
        awkParserAdvance(p);
    } else {
        awkSyntaxError(p, "expected function name");
    }
    awkExpect(p, AWK_TOK_LPAREN, "'('");
    int pcount = 0;
    char **params = NULL;
    if (!awkCheck(p, AWK_TOK_RPAREN)) {
        for (;;) {
            if (!awkCheck(p, AWK_TOK_NAME)) { awkSyntaxError(p, "expected parameter name"); break; }
            params = (char **)realloc(params, sizeof(char *) * (size_t)(pcount + 1));
            params[pcount++] = strdup(p->cur.text);
            awkParserAdvance(p);
            if (!awkAccept(p, AWK_TOK_COMMA)) break;
            awkSkipOptNewlines(p);
        }
    }
    awkExpect(p, AWK_TOK_RPAREN, "')'");
    n->params = params;
    n->paramCount = pcount;
    awkSkipOptNewlines(p);
    n->a = parseBlock(p);
    return n;
}

AwkProgram *awkParseProgram(const char *src) {
    AwkParser parser;
    memset(&parser, 0, sizeof(parser));
    awkLexerInit(&parser.lx, src);
    parser.cur = awkLexerNext(&parser.lx);

    AwkProgram *prog = (AwkProgram *)calloc(1, sizeof(AwkProgram));
    awkSkipTerms(&parser);
    while (!awkCheck(&parser, AWK_TOK_EOF) && !parser.error) {
        AwkNode *item;
        if (awkCheck(&parser, AWK_TOK_FUNCTION)) {
            item = parseFunctionDef(&parser);
        } else {
            AwkPatternKind kind;
            AwkNode *pat = parsePattern(&parser, &kind);
            item = awkNewNode(AWK_ITEM_RULE);
            item->patKind = kind;
            if (kind == AWK_PAT_RANGE) {
                item->a = pat->a;
                item->b = pat->b;
                free(pat);
            } else {
                item->a = pat;
            }
            awkSkipOptNewlines(&parser);
            if (awkCheck(&parser, AWK_TOK_LBRACE)) {
                item->c = parseBlock(&parser);
            }
        }
        prog->items = (AwkNode **)realloc(prog->items, sizeof(AwkNode *) * (size_t)(prog->itemCount + 1));
        prog->items[prog->itemCount++] = item;
        awkSkipTerms(&parser);
    }

    awkTokenFree(&parser.cur);
    if (parser.error) {
        free(prog->items);
        free(prog);
        return NULL;
    }
    return prog;
}
