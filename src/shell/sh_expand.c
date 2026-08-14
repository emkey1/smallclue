/* POSIX word expansion: tilde, parameter, command substitution, arithmetic,
 * field splitting, pathname expansion, quote removal.
 *
 * Word text arrives from the vendored exsh lexer in "marked" form: quote
 * boundaries are SHELL_QUOTE_MARK_SINGLE/DOUBLE bytes, backslash-escaped
 * characters are prefixed with SHELL_ESCAPE_MARK, and all $-expansions are
 * kept verbatim (raw source). Text nested inside ${...} operands, $(...),
 * and here-documents is raw shell source, so the expander runs in either
 * "marked" or "raw" mode as it descends.
 *
 * Expansion builds a byte buffer with per-byte flags; field splitting and
 * globbing consult the flags so that quoted bytes are never split or
 * glob-active, matching POSIX semantics. */

#include "sh_interp.h"
#include "quote_markers.h"

#include <ctype.h>
#include <fnmatch.h>
#include <glob.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CH_QUOTED     0x01  /* not subject to splitting or globbing */
#define CH_FROM_EXP   0x02  /* produced by an expansion (splittable) */
#define CH_FIELD_SEP  0x04  /* hard field break (from "$@") */
#define CH_PLACEHOLDER 0x08 /* zero-width "a quoted region was here" */

typedef struct {
    char *bytes;
    unsigned char *flags;
    size_t len;
    size_t cap;
} ExpBuf;

typedef struct {
    ShInterp *interp;
    ExpBuf buf;
    bool error;        /* fatal expansion error (${var?}) */
    bool saw_quote;    /* word contained any quoting at all */
    size_t quote_open_len;  /* buffer length when the current quote opened */
    bool at_empty_in_quote; /* "$@"/"$*" with zero params inside this quote */
    bool squashed_empty_at; /* $@ expanded with zero params anywhere in word */
} ExpCtx;

static void expBufPush(ExpBuf *buf, char c, unsigned char flags) {
    if (buf->len + 1 > buf->cap) {
        size_t cap = buf->cap ? buf->cap * 2 : 64;
        char *nb = (char *)realloc(buf->bytes, cap);
        unsigned char *nf = (unsigned char *)realloc(buf->flags, cap);
        if (!nb || !nf) {
            free(nb == buf->bytes ? NULL : nb);
            free(nf == buf->flags ? NULL : nf);
            return;
        }
        buf->bytes = nb;
        buf->flags = nf;
        buf->cap = cap;
    }
    buf->bytes[buf->len] = c;
    buf->flags[buf->len] = flags;
    buf->len++;
}

static void expBufPushStr(ExpBuf *buf, const char *s, unsigned char flags) {
    while (s && *s) {
        expBufPush(buf, *s++, flags);
    }
}

static void expBufFree(ExpBuf *buf) {
    free(buf->bytes);
    free(buf->flags);
    memset(buf, 0, sizeof(*buf));
}

/* ---- small helpers -------------------------------------------------------- */

static bool isNameStart(unsigned char c) {
    return c == '_' || isalpha(c) || c >= 0x80;
}

static bool isNameChar(unsigned char c) {
    return c == '_' || isalnum(c) || c >= 0x80;
}

static const char *specialParam(ShInterp *interp, char c, char *scratch, size_t scratch_len) {
    switch (c) {
        case '?':
            snprintf(scratch, scratch_len, "%d", interp->last_status);
            return scratch;
        case '$':
            snprintf(scratch, scratch_len, "%ld", (long)interp->shell_pid);
            return scratch;
        case '!':
            if (interp->last_bg_pid <= 0) {
                return "";
            }
            snprintf(scratch, scratch_len, "%ld", (long)interp->last_bg_pid);
            return scratch;
        case '#':
            snprintf(scratch, scratch_len, "%d", interp->param_count);
            return scratch;
        case '-': {
            size_t n = 0;
            if (interp->opt_allexport && n < scratch_len - 1) scratch[n++] = 'a';
            if (interp->opt_noclobber && n < scratch_len - 1) scratch[n++] = 'C';
            if (interp->opt_errexit && n < scratch_len - 1) scratch[n++] = 'e';
            if (interp->opt_noglob && n < scratch_len - 1) scratch[n++] = 'f';
            if (interp->interactive && n < scratch_len - 1) scratch[n++] = 'i';
            if (interp->opt_monitor && n < scratch_len - 1) scratch[n++] = 'm';
            if (interp->opt_noexec && n < scratch_len - 1) scratch[n++] = 'n';
            if (interp->opt_nounset && n < scratch_len - 1) scratch[n++] = 'u';
            if (interp->opt_verbose && n < scratch_len - 1) scratch[n++] = 'v';
            if (interp->opt_xtrace && n < scratch_len - 1) scratch[n++] = 'x';
            scratch[n] = '\0';
            return scratch;
        }
        default:
            return NULL;
    }
}

static const char *positionalParam(ShInterp *interp, int index) {
    if (index == 0) {
        return interp->arg0 ? interp->arg0 : "sh";
    }
    if (index >= 1 && index <= interp->param_count) {
        return interp->params[index - 1];
    }
    return NULL;
}

static char ifsFirstSeparator(ShInterp *interp) {
    const char *ifs = shVarGet(interp, "IFS");
    if (!ifs) {
        return ' ';
    }
    return ifs[0]; /* may be NUL: join with nothing */
}

/* ---- forward decls -------------------------------------------------------- */

typedef enum {
    MODE_MARKED,   /* lexer-marked word text */
    MODE_RAW,      /* raw sh fragment (inside ${...} operand) */
    MODE_HEREDOC   /* raw heredoc body: only $, `, and \ before $`"\ are live */
} ExpandMode;

static void expandText(ExpCtx *ctx, const char *text, size_t len, ExpandMode mode,
                       bool in_dquotes, bool tilde_ok);
static size_t expandDollar(ExpCtx *ctx, const char *text, size_t len, size_t i,
                           bool in_dquotes);

static void emitUnsetError(ExpCtx *ctx, const char *name, const char *msg) {
    fprintf(stderr, "sh: %s: %s\n", name, msg && *msg ? msg : "parameter not set");
    ctx->error = true;
    if (!ctx->interp->interactive) {
        ctx->interp->flow = SH_FLOW_EXIT;
        ctx->interp->exit_status = 2; /* set -u violation: sh convention */
    }
}

/* Emit the positional parameters for $@/$* with the given quoting context. */
static void emitAllParams(ExpCtx *ctx, char which, bool in_dquotes) {
    ShInterp *interp = ctx->interp;
    unsigned char flags = CH_FROM_EXP | (in_dquotes ? CH_QUOTED : 0);
    if (interp->param_count == 0) {
        /* "$@" with no params: zero fields, no empty-field marker */
        ctx->at_empty_in_quote = true;
        ctx->squashed_empty_at = true;
        return;
    }
    for (int i = 0; i < interp->param_count; ++i) {
        if (i > 0) {
            if (in_dquotes && which == '@') {
                expBufPush(&ctx->buf, '\0', CH_FIELD_SEP);
            } else if (in_dquotes && which == '*') {
                char sep = ifsFirstSeparator(interp);
                if (sep != '\0') {
                    expBufPush(&ctx->buf, sep, flags);
                }
            } else {
                /* unquoted $@/$*: separator is a splittable space */
                expBufPush(&ctx->buf, ' ', CH_FROM_EXP);
            }
        }
        expBufPushStr(&ctx->buf, interp->params[i], flags);
        if (in_dquotes && interp->params[i][0] == '\0') {
            expBufPush(&ctx->buf, '\0', CH_PLACEHOLDER | CH_QUOTED);
        }
    }
}

/* ---- ${...} --------------------------------------------------------------- */

/* Expand a ${...} span. `body` is the raw text between the braces. */
static void expandBracedParam(ExpCtx *ctx, const char *body, size_t body_len,
                              bool in_dquotes) {
    ShInterp *interp = ctx->interp;
    unsigned char flags = CH_FROM_EXP | (in_dquotes ? CH_QUOTED : 0);
    char scratch[64];

    if (body_len == 0) {
        fprintf(stderr, "sh: bad substitution: ${}\n");
        ctx->error = true;
        return;
    }

    /* ${#param}: length */
    if (body[0] == '#' && body_len > 1) {
        const char *name = body + 1;
        size_t name_len = body_len - 1;
        char *nbuf = strndup(name, name_len);
        const char *val = NULL;
        if (name_len == 1 && strchr("@*", nbuf[0])) {
            snprintf(scratch, sizeof(scratch), "%d", interp->param_count);
            expBufPushStr(&ctx->buf, scratch, flags);
            free(nbuf);
            return;
        }
        if (name_len == 1 && isdigit((unsigned char)nbuf[0])) {
            val = positionalParam(interp, nbuf[0] - '0');
        } else if (name_len >= 1 && isdigit((unsigned char)nbuf[0])) {
            val = positionalParam(interp, atoi(nbuf));
        } else if (name_len == 1 && specialParam(interp, nbuf[0], scratch, sizeof(scratch))) {
            val = specialParam(interp, nbuf[0], scratch, sizeof(scratch));
        } else {
            val = shVarGet(interp, nbuf);
        }
        snprintf(scratch, sizeof(scratch), "%zu", val ? strlen(val) : 0);
        expBufPushStr(&ctx->buf, scratch, flags);
        free(nbuf);
        return;
    }

    /* Parse the parameter name. */
    size_t i = 0;
    char name[256];
    size_t name_len = 0;
    if (isdigit((unsigned char)body[0])) {
        while (i < body_len && isdigit((unsigned char)body[i]) && name_len < sizeof(name) - 1) {
            name[name_len++] = body[i++];
        }
    } else if (strchr("@*#?$!-", body[0])) {
        name[name_len++] = body[i++];
    } else if (isNameStart((unsigned char)body[0])) {
        while (i < body_len && isNameChar((unsigned char)body[i]) && name_len < sizeof(name) - 1) {
            name[name_len++] = body[i++];
        }
    }
    name[name_len] = '\0';
    if (name_len == 0) {
        fprintf(stderr, "sh: bad substitution: ${%.*s}\n", (int)body_len, body);
        ctx->error = true;
        return;
    }

    /* Fetch the value. */
    const char *value = NULL;
    bool is_at_star = (name_len == 1 && (name[0] == '@' || name[0] == '*'));
    if (is_at_star) {
        /* handled specially below */
    } else if (isdigit((unsigned char)name[0])) {
        value = positionalParam(interp, atoi(name));
    } else if (name_len == 1 && specialParam(interp, name[0], scratch, sizeof(scratch))) {
        value = specialParam(interp, name[0], scratch, sizeof(scratch));
    } else {
        value = shVarGet(interp, name);
    }

    /* Bare ${name}. */
    if (i >= body_len) {
        if (is_at_star) {
            emitAllParams(ctx, name[0], in_dquotes);
            return;
        }
        if (!value) {
            if (interp->opt_nounset) {
                emitUnsetError(ctx, name, "parameter not set");
            }
            return;
        }
        expBufPushStr(&ctx->buf, value, flags);
        return;
    }

    /* Operator. */
    bool colon = false;
    if (body[i] == ':' && i + 1 < body_len && strchr("-=?+", body[i + 1])) {
        colon = true;
        i++;
    }
    char op = body[i];
    if (op == '%' || op == '#') {
        bool longest = (i + 1 < body_len && body[i + 1] == op);
        size_t pat_start = i + (longest ? 2 : 1);
        const char *pat_raw = body + pat_start;
        size_t pat_len = body_len - pat_start;

        const char *subject = value ? value : "";
        if (is_at_star) {
            subject = interp->param_count > 0 ? interp->params[0] : "";
        }

        /* Expand the pattern fragment (raw mode), keeping quoting flags so
         * quoted chars match literally. */
        ExpCtx pat_ctx = {ctx->interp, {0}, false, false};
        expandText(&pat_ctx, pat_raw, pat_len, MODE_RAW, false, false);
        if (pat_ctx.error) {
            ctx->error = true;
            expBufFree(&pat_ctx.buf);
            return;
        }
        /* Build an fnmatch pattern: escape quoted specials. */
        size_t plen = pat_ctx.buf.len;
        char *pattern = (char *)malloc(plen * 2 + 1);
        size_t pn = 0;
        for (size_t p = 0; p < plen; ++p) {
            char c = pat_ctx.buf.bytes[p];
            if (pat_ctx.buf.flags[p] & CH_PLACEHOLDER) {
                continue;
            }
            if ((pat_ctx.buf.flags[p] & CH_QUOTED) && strchr("*?[]\\", c)) {
                pattern[pn++] = '\\';
            }
            pattern[pn++] = c;
        }
        pattern[pn] = '\0';
        expBufFree(&pat_ctx.buf);

        size_t slen = strlen(subject);
        char *tmp = strdup(subject);
        const char *result = subject;
        if (op == '#') {
            /* prefix removal */
            if (longest) {
                for (size_t cut = slen + 1; cut-- > 0;) {
                    char saved = tmp[cut];
                    tmp[cut] = '\0';
                    int m = fnmatch(pattern, tmp, 0);
                    tmp[cut] = saved;
                    if (m == 0) {
                        result = subject + cut;
                        break;
                    }
                }
            } else {
                for (size_t cut = 0; cut <= slen; ++cut) {
                    char saved = tmp[cut];
                    tmp[cut] = '\0';
                    int m = fnmatch(pattern, tmp, 0);
                    tmp[cut] = saved;
                    if (m == 0) {
                        result = subject + cut;
                        break;
                    }
                }
            }
            expBufPushStr(&ctx->buf, result, flags);
        } else {
            /* suffix removal */
            size_t keep = slen;
            if (longest) {
                for (size_t start = 0; start <= slen; ++start) {
                    if (fnmatch(pattern, subject + start, 0) == 0) {
                        keep = start;
                        break;
                    }
                }
            } else {
                for (size_t start = slen + 1; start-- > 0;) {
                    if (fnmatch(pattern, subject + start, 0) == 0) {
                        keep = start;
                        break;
                    }
                }
            }
            for (size_t p = 0; p < keep; ++p) {
                expBufPush(&ctx->buf, subject[p], flags);
            }
        }
        free(tmp);
        free(pattern);
        return;
    }

    if (!strchr("-=?+", op)) {
        fprintf(stderr, "sh: bad substitution: ${%.*s}\n", (int)body_len, body);
        ctx->error = true;
        return;
    }

    const char *word = body + i + 1;
    size_t word_len = body_len - i - 1;
    bool have = is_at_star ? (interp->param_count > 0) : (value != NULL);
    bool usable = have && (!colon || (is_at_star || (value && value[0] != '\0')));

    switch (op) {
        case '-':
            if (usable) {
                if (is_at_star) {
                    emitAllParams(ctx, name[0], in_dquotes);
                } else {
                    expBufPushStr(&ctx->buf, value, flags);
                }
            } else {
                expandText(ctx, word, word_len, MODE_RAW, in_dquotes, false);
            }
            break;
        case '=': {
            if (usable) {
                if (is_at_star) {
                    emitAllParams(ctx, name[0], in_dquotes);
                } else {
                    expBufPushStr(&ctx->buf, value, flags);
                }
            } else {
                if (is_at_star || isdigit((unsigned char)name[0]) ||
                    (name_len == 1 && specialParam(interp, name[0], scratch, sizeof(scratch)))) {
                    fprintf(stderr, "sh: ${%s=...}: cannot assign\n", name);
                    ctx->error = true;
                    return;
                }
                ExpCtx sub = {ctx->interp, {0}, false, false};
                expandText(&sub, word, word_len, MODE_RAW, false, false);
                char *assigned = strndup(sub.buf.bytes ? sub.buf.bytes : "", sub.buf.len);
                /* strip placeholders */
                size_t w = 0;
                for (size_t p = 0; p < sub.buf.len; ++p) {
                    if (!(sub.buf.flags[p] & CH_PLACEHOLDER)) {
                        assigned[w++] = sub.buf.bytes[p];
                    }
                }
                assigned[w] = '\0';
                expBufFree(&sub.buf);
                shVarSet(interp, name, assigned, false);
                expBufPushStr(&ctx->buf, assigned, flags);
                free(assigned);
            }
            break;
        }
        case '?':
            if (usable) {
                if (is_at_star) {
                    emitAllParams(ctx, name[0], in_dquotes);
                } else {
                    expBufPushStr(&ctx->buf, value, flags);
                }
            } else {
                char *msg = strndup(word, word_len);
                emitUnsetError(ctx, name, msg && *msg ? msg : NULL);
                free(msg);
            }
            break;
        case '+':
            if (usable) {
                expandText(ctx, word, word_len, MODE_RAW, in_dquotes, false);
            }
            break;
    }
}

/* ---- command substitution scanning ---------------------------------------- */

/* Find the end of a $( ... ) span starting just after the '('.
 * Respects nesting, single/double quotes, and backslashes. Returns the
 * index of the closing ')' or len if unterminated. */
static size_t scanDollarParen(const char *text, size_t len, size_t start) {
    int depth = 1;
    bool in_squote = false, in_dquote = false;
    for (size_t i = start; i < len; ++i) {
        char c = text[i];
        if (in_squote) {
            if (c == '\'') in_squote = false;
            continue;
        }
        if (c == '\\') {
            i++;
            continue;
        }
        if (in_dquote) {
            if (c == '"') in_dquote = false;
            continue;
        }
        if (c == '\'') in_squote = true;
        else if (c == '"') in_dquote = true;
        else if (c == '(') depth++;
        else if (c == ')') {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }
    return len;
}

/* Find the end of a ${ ... } span starting just after the '{'. */
static size_t scanDollarBrace(const char *text, size_t len, size_t start) {
    int depth = 1;
    bool in_squote = false, in_dquote = false;
    for (size_t i = start; i < len; ++i) {
        char c = text[i];
        if (in_squote) {
            if (c == '\'') in_squote = false;
            continue;
        }
        if (c == '\\') {
            i++;
            continue;
        }
        if (in_dquote) {
            if (c == '"') in_dquote = false;
            continue;
        }
        if (c == '\'') in_squote = true;
        else if (c == '"') in_dquote = true;
        else if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }
    return len;
}

/* Find matching )) for $(( ... )). Returns index of the first ')' of the
 * closing pair, or len. */
static size_t scanDoubleParen(const char *text, size_t len, size_t start) {
    int depth = 2;
    for (size_t i = start; i < len; ++i) {
        char c = text[i];
        if (c == '(') depth++;
        else if (c == ')') {
            depth--;
            if (depth == 0) {
                return i - 1; /* i is the second ')' */
            }
        }
    }
    return len;
}

static size_t scanBacktick(const char *text, size_t len, size_t start) {
    for (size_t i = start; i < len; ++i) {
        if (text[i] == '\\' && i + 1 < len) {
            i++;
            continue;
        }
        if (text[i] == '`') {
            return i;
        }
    }
    return len;
}

static char *unescapeBacktickBody(const char *body, size_t len) {
    char *out = (char *)malloc(len + 1);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = body[i];
        if (c == SHELL_QUOTE_MARK_SINGLE) {
            out[j++] = '\'';
            continue;
        }
        if (c == SHELL_QUOTE_MARK_DOUBLE) {
            out[j++] = '"';
            continue;
        }
        if (c == SHELL_ESCAPE_MARK && i + 1 < len) {
            out[j++] = body[++i];
            continue;
        }
        if (c == '\\' && i + 1 < len) {
            char next = body[i + 1];
            if (next == '\\' || next == '`' || next == '$') {
                out[j++] = next;
                i++;
                continue;
            }
            if (next == '\n') {
                i++;
                continue;
            }
        }
        out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

static void insertCommandOutput(ExpCtx *ctx, const char *command, bool in_dquotes) {
    char *output = NULL;
    int status = shCommandSubstitution(ctx->interp, command, &output);
    ctx->interp->last_status = status;
    ctx->interp->subst_status = status;
    ctx->interp->subst_ran = true;
    if (!output) {
        return;
    }
    /* Strip trailing newlines. */
    size_t olen = strlen(output);
    while (olen > 0 && output[olen - 1] == '\n') {
        olen--;
    }
    unsigned char flags = CH_FROM_EXP | (in_dquotes ? CH_QUOTED : 0);
    for (size_t i = 0; i < olen; ++i) {
        expBufPush(&ctx->buf, output[i], flags);
    }
    free(output);
}

/* ---- $ dispatch ------------------------------------------------------------ */

/* Handles the span starting at text[i] == '$'. Returns the index of the
 * first character after the span. */
static size_t expandDollar(ExpCtx *ctx, const char *text, size_t len, size_t i,
                           bool in_dquotes) {
    ShInterp *interp = ctx->interp;
    unsigned char flags = CH_FROM_EXP | (in_dquotes ? CH_QUOTED : 0);
    char scratch[64];

    if (i + 1 >= len) {
        expBufPush(&ctx->buf, '$', in_dquotes ? CH_QUOTED : 0);
        return i + 1;
    }
    char next = text[i + 1];

    if (next == '(') {
        if (i + 2 < len && text[i + 2] == '(') {
            /* $(( arithmetic )) */
            size_t close = scanDoubleParen(text, len, i + 3);
            if (close >= len) {
                expBufPush(&ctx->buf, '$', in_dquotes ? CH_QUOTED : 0);
                return i + 1;
            }
            char *expr = strndup(text + i + 3, close - (i + 3));
            long long result = 0;
            if (shArithEval(interp, expr, &result) != 0) {
                ctx->error = true;
            } else {
                snprintf(scratch, sizeof(scratch), "%lld", result);
                expBufPushStr(&ctx->buf, scratch, flags);
            }
            free(expr);
            return close + 2;
        }
        /* $( command ) */
        size_t close = scanDollarParen(text, len, i + 2);
        char *command = strndup(text + i + 2, close - (i + 2));
        insertCommandOutput(ctx, command, in_dquotes);
        free(command);
        return close < len ? close + 1 : len;
    }

    if (next == '{') {
        size_t close = scanDollarBrace(text, len, i + 2);
        expandBracedParam(ctx, text + i + 2, close - (i + 2), in_dquotes);
        return close < len ? close + 1 : len;
    }

    if (isdigit((unsigned char)next)) {
        const char *val = positionalParam(interp, next - '0');
        if (val) {
            expBufPushStr(&ctx->buf, val, flags);
        } else if (interp->opt_nounset) {
            char pname[2] = {next, 0};
            emitUnsetError(ctx, pname, "parameter not set");
        }
        return i + 2;
    }

    if (next == '@' || next == '*') {
        emitAllParams(ctx, next, in_dquotes);
        return i + 2;
    }

    if (specialParam(interp, next, scratch, sizeof(scratch))) {
        expBufPushStr(&ctx->buf, specialParam(interp, next, scratch, sizeof(scratch)), flags);
        return i + 2;
    }

    if (isNameStart((unsigned char)next)) {
        size_t j = i + 1;
        while (j < len && isNameChar((unsigned char)text[j])) {
            j++;
        }
        char *name = strndup(text + i + 1, j - (i + 1));
        const char *val = shVarGet(interp, name);
        if (val) {
            expBufPushStr(&ctx->buf, val, flags);
        } else if (interp->opt_nounset) {
            emitUnsetError(ctx, name, "parameter not set");
        }
        free(name);
        return j;
    }

    /* Literal $ */
    expBufPush(&ctx->buf, '$', in_dquotes ? CH_QUOTED : 0);
    return i + 1;
}

/* ---- tilde ----------------------------------------------------------------- */

/* Expand a leading ~ (or ~user) if present. Returns chars consumed. */
static size_t expandTilde(ExpCtx *ctx, const char *text, size_t len, ExpandMode mode) {
    if (len == 0 || text[0] != '~') {
        return 0;
    }
    size_t end = 0;
    while (end < len) {
        char c = text[end];
        if (c == '/' || c == SHELL_QUOTE_MARK_SINGLE || c == SHELL_QUOTE_MARK_DOUBLE ||
            c == SHELL_ESCAPE_MARK || c == '$' || c == '`' ||
            (mode != MODE_MARKED && (c == '\'' || c == '"' || c == '\\'))) {
            break;
        }
        end++;
    }
    /* Anything quoted inside the candidate kills tilde expansion. */
    for (size_t i = 0; i < end; ++i) {
        char c = text[i];
        if (c == SHELL_QUOTE_MARK_SINGLE || c == SHELL_QUOTE_MARK_DOUBLE || c == SHELL_ESCAPE_MARK) {
            return 0;
        }
    }
    const char *home = NULL;
    if (end == 1) {
        home = shVarGet(ctx->interp, "HOME");
        if (!home) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : NULL;
        }
    } else {
        char *user = strndup(text + 1, end - 1);
        struct passwd *pw = user ? getpwnam(user) : NULL;
        free(user);
        home = pw ? pw->pw_dir : NULL;
    }
    if (!home) {
        return 0; /* leave the word alone */
    }
    /* Tilde result is not subject to field splitting or globbing. */
    expBufPushStr(&ctx->buf, home, CH_QUOTED);
    return end;
}

/* ---- main text walk --------------------------------------------------------- */

static void expandText(ExpCtx *ctx, const char *text, size_t len, ExpandMode mode,
                       bool in_dquotes, bool tilde_ok) {
    bool in_squotes = false;
    size_t i = 0;

    if (tilde_ok && !in_dquotes && !ctx->interp->in_subshell) {
        i = expandTilde(ctx, text, len, mode);
    } else if (tilde_ok && !in_dquotes) {
        i = expandTilde(ctx, text, len, mode);
    }

    for (; i < len;) {
        char c = text[i];

        if (mode == MODE_MARKED) {
            if (c == SHELL_QUOTE_MARK_SINGLE) {
                bool entering = !in_squotes;
                in_squotes = !in_squotes;
                ctx->saw_quote = true;
                if (entering) {
                    ctx->quote_open_len = ctx->buf.len;
                    ctx->at_empty_in_quote = false;
                } else if (ctx->buf.len == ctx->quote_open_len && !ctx->at_empty_in_quote) {
                    /* '' contributed nothing: zero-width "keep this field" marker */
                    expBufPush(&ctx->buf, '\0', CH_PLACEHOLDER | CH_QUOTED);
                }
                i++;
                continue;
            }
            if (c == SHELL_QUOTE_MARK_DOUBLE && !in_squotes) {
                bool entering = !in_dquotes;
                in_dquotes = !in_dquotes;
                ctx->saw_quote = true;
                if (entering) {
                    ctx->quote_open_len = ctx->buf.len;
                    ctx->at_empty_in_quote = false;
                } else if (ctx->buf.len == ctx->quote_open_len && !ctx->at_empty_in_quote) {
                    expBufPush(&ctx->buf, '\0', CH_PLACEHOLDER | CH_QUOTED);
                }
                i++;
                continue;
            }
            if (c == SHELL_ESCAPE_MARK && i + 1 < len) {
                expBufPush(&ctx->buf, text[i + 1], CH_QUOTED);
                ctx->saw_quote = true;
                i += 2;
                continue;
            }
            if (in_squotes) {
                expBufPush(&ctx->buf, c, CH_QUOTED);
                i++;
                continue;
            }
        } else {
            /* RAW / HEREDOC modes: real quote characters are live. */
            if (mode == MODE_RAW) {
                if (in_squotes) {
                    if (c == '\'') {
                        in_squotes = false;
                        if (ctx->buf.len == ctx->quote_open_len) {
                            expBufPush(&ctx->buf, '\0', CH_PLACEHOLDER | CH_QUOTED);
                        }
                    } else {
                        expBufPush(&ctx->buf, c, CH_QUOTED);
                    }
                    i++;
                    continue;
                }
                if (c == '\'' && !in_dquotes) {
                    in_squotes = true;
                    ctx->saw_quote = true;
                    ctx->quote_open_len = ctx->buf.len;
                    i++;
                    continue;
                }
                if (c == '"') {
                    in_dquotes = !in_dquotes;
                    ctx->saw_quote = true;
                    if (in_dquotes) {
                        ctx->quote_open_len = ctx->buf.len;
                        ctx->at_empty_in_quote = false;
                    } else if (ctx->buf.len == ctx->quote_open_len && !ctx->at_empty_in_quote) {
                        expBufPush(&ctx->buf, '\0', CH_PLACEHOLDER | CH_QUOTED);
                    }
                    i++;
                    continue;
                }
                if (c == '\\' && i + 1 < len) {
                    char n = text[i + 1];
                    if (in_dquotes) {
                        if (n == '$' || n == '`' || n == '"' || n == '\\') {
                            expBufPush(&ctx->buf, n, CH_QUOTED);
                            i += 2;
                            continue;
                        }
                        if (n == '\n') {
                            i += 2;
                            continue;
                        }
                    } else {
                        if (n == '\n') {
                            i += 2;
                            continue;
                        }
                        expBufPush(&ctx->buf, n, CH_QUOTED);
                        ctx->saw_quote = true;
                        i += 2;
                        continue;
                    }
                }
            } else { /* MODE_HEREDOC */
                if (c == '\\' && i + 1 < len) {
                    char n = text[i + 1];
                    if (n == '$' || n == '`' || n == '\\') {
                        expBufPush(&ctx->buf, n, CH_QUOTED);
                        i += 2;
                        continue;
                    }
                    if (n == '\n') {
                        i += 2;
                        continue;
                    }
                }
            }
        }

        if (c == '$') {
            i = expandDollar(ctx, text, len, i, in_dquotes || mode == MODE_HEREDOC);
            continue;
        }
        if (c == '`') {
            size_t close = scanBacktick(text, len, i + 1);
            char *body = unescapeBacktickBody(text + i + 1, close - (i + 1));
            if (body) {
                insertCommandOutput(ctx, body, in_dquotes || mode == MODE_HEREDOC);
                free(body);
            }
            i = close < len ? close + 1 : len;
            continue;
        }

        unsigned char flags = 0;
        if (in_dquotes || mode == MODE_HEREDOC) {
            flags = CH_QUOTED;
        }
        expBufPush(&ctx->buf, c, flags);
        i++;
    }
}

/* ---- field splitting -------------------------------------------------------- */

static bool ifsContains(const char *ifs, char c) {
    return c != '\0' && ifs && strchr(ifs, c) != NULL;
}

static bool isIfsWhitespace(const char *ifs, char c) {
    return ifsContains(ifs, c) && (c == ' ' || c == '\t' || c == '\n');
}

/* ---- globbing ---------------------------------------------------------------- */

/* Does the field (built from buffer range) contain an active glob char? */
static bool bufHasGlobChars(const ExpBuf *buf) {
    for (size_t i = 0; i < buf->len; ++i) {
        if (buf->flags[i] & (CH_QUOTED | CH_PLACEHOLDER)) {
            continue;
        }
        char c = buf->bytes[i];
        if (c == '*' || c == '?' || c == '[') {
            return true;
        }
    }
    return false;
}

/* ---- public API ---------------------------------------------------------------- */

/* Rebuild per-field flag info: splitIntoFields loses flags, so for globbing
 * we re-run expansion per word and glob before splitting is not correct
 * either. Instead: split first into (bytes,flags) fields, then glob.
 * To keep the plumbing simple we glob on the whole-word buffer only when
 * the word produces exactly the fields unsplit; for split results we
 * conservatively re-check each field for glob chars (quoted state is gone,
 * but quoted glob chars were already handled during pattern build).
 *
 * Practical approach: perform splitting on the flag buffer directly into
 * sub-buffers (keeping flags), then glob each sub-buffer. */

typedef struct {
    ExpBuf *items;
    size_t count;
    size_t capacity;
} BufList;

static void bufListPush(BufList *list, ExpBuf buf) {
    if (list->count + 1 > list->capacity) {
        size_t cap = list->capacity ? list->capacity * 2 : 8;
        ExpBuf *tmp = (ExpBuf *)realloc(list->items, cap * sizeof(ExpBuf));
        if (!tmp) {
            return;
        }
        list->items = tmp;
        list->capacity = cap;
    }
    list->items[list->count++] = buf;
}

/* Split the whole-word buffer into per-field buffers preserving flags. */
static void splitBufIntoBufs(ShInterp *interp, const ExpBuf *buf, bool saw_quote, BufList *out) {
    const char *ifs = shVarGet(interp, "IFS");
    if (!ifs) {
        ifs = " \t\n";
    }
    size_t n = buf->len;
    size_t i = 0;

    ExpBuf cur = {0};
    bool cur_has_content = false; /* any byte or placeholder seen */

    while (i < n && (buf->flags[i] & CH_FROM_EXP) && !(buf->flags[i] & CH_QUOTED) &&
           isIfsWhitespace(ifs, buf->bytes[i])) {
        i++;
    }

    bool pending_delim = false;
    for (; i < n; ++i) {
        char c = buf->bytes[i];
        unsigned char fl = buf->flags[i];

        if (fl & CH_FIELD_SEP) {
            bufListPush(out, cur);
            memset(&cur, 0, sizeof(cur));
            expBufPush(&cur, '\0', CH_PLACEHOLDER | CH_QUOTED);
            cur_has_content = true;
            continue;
        }
        bool splittable = (fl & CH_FROM_EXP) && !(fl & CH_QUOTED) && !(fl & CH_PLACEHOLDER);
        if (splittable && ifsContains(ifs, c)) {
            if (cur_has_content) {
                bufListPush(out, cur);
                memset(&cur, 0, sizeof(cur));
                cur_has_content = false;
            }
            bool nonws = !isIfsWhitespace(ifs, c);
            /* absorb run: ws* [nonws ws*]? — one non-ws delimiter max */
            size_t j = i + 1;
            bool consumed_nonws = nonws;
            while (j < n) {
                unsigned char fj = buf->flags[j];
                bool splittable_j = (fj & CH_FROM_EXP) && !(fj & CH_QUOTED) && !(fj & CH_PLACEHOLDER);
                if (!splittable_j || !ifsContains(ifs, buf->bytes[j])) {
                    break;
                }
                if (!isIfsWhitespace(ifs, buf->bytes[j])) {
                    if (consumed_nonws) {
                        break;
                    }
                    consumed_nonws = true;
                }
                j++;
            }
            i = j - 1;
            pending_delim = consumed_nonws;
            continue;
        }
        expBufPush(&cur, c, fl);
        cur_has_content = true;
        pending_delim = false;
    }
    if (cur_has_content) {
        bufListPush(out, cur);
    } else if (pending_delim) {
        /* trailing non-ws IFS: a:b: -> "a" "b" "" */
        bufListPush(out, cur);
    } else if (out->count == 0 && saw_quote) {
        /* only empty quotes: one empty field */
        expBufPush(&cur, '\0', CH_PLACEHOLDER | CH_QUOTED);
        bufListPush(out, cur);
    } else {
        expBufFree(&cur);
    }
}

static char *bufToPlainString(const ExpBuf *buf) {
    char *s = (char *)malloc(buf->len + 1);
    if (!s) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < buf->len; ++i) {
        if (buf->flags[i] & CH_PLACEHOLDER) {
            continue;
        }
        s[j++] = buf->bytes[i];
    }
    s[j] = '\0';
    return s;
}

static char *bufToGlobPattern(const ExpBuf *buf) {
    char *s = (char *)malloc(buf->len * 2 + 1);
    if (!s) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < buf->len; ++i) {
        if (buf->flags[i] & CH_PLACEHOLDER) {
            continue;
        }
        char c = buf->bytes[i];
        if ((buf->flags[i] & CH_QUOTED) && strchr("*?[]\\", c)) {
            s[j++] = '\\';
        } else if (!(buf->flags[i] & CH_QUOTED) && c == '\\') {
            s[j++] = '\\';
        }
        s[j++] = c;
    }
    s[j] = '\0';
    return s;
}

int shExpandWord(ShInterp *interp, const ShellWord *word, ShFields *out) {
    if (!word || !word->text) {
        return 0;
    }
    ExpCtx ctx = {interp, {0}, false, false};
    expandText(&ctx, word->text, strlen(word->text), MODE_MARKED, false, true);
    if (ctx.error) {
        expBufFree(&ctx.buf);
        return 1;
    }

    BufList fields = {0};
    bool saw_quote = ctx.saw_quote && !(ctx.buf.len == 0 && ctx.squashed_empty_at);
    splitBufIntoBufs(interp, &ctx.buf, saw_quote, &fields);
    expBufFree(&ctx.buf);

    for (size_t f = 0; f < fields.count; ++f) {
        ExpBuf *fb = &fields.items[f];
        if (!interp->opt_noglob && bufHasGlobChars(fb)) {
            char *pattern = bufToGlobPattern(fb);
            glob_t gl;
            memset(&gl, 0, sizeof(gl));
            int rc = pattern ? glob(pattern, 0, NULL, &gl) : GLOB_NOMATCH;
            if (rc == 0 && gl.gl_pathc > 0) {
                for (size_t g = 0; g < gl.gl_pathc; ++g) {
                    shFieldsPush(out, strdup(gl.gl_pathv[g]));
                }
                globfree(&gl);
                free(pattern);
                expBufFree(fb);
                continue;
            }
            if (rc == 0) {
                globfree(&gl);
            }
            free(pattern);
        }
        char *plain = bufToPlainString(fb);
        if (plain) {
            shFieldsPush(out, plain);
        }
        expBufFree(fb);
    }
    free(fields.items);
    return 0;
}

char *shExpandWordSingle(ShInterp *interp, const ShellWord *word) {
    if (!word || !word->text) {
        return strdup("");
    }
    ExpCtx ctx = {interp, {0}, false, false};
    expandText(&ctx, word->text, strlen(word->text), MODE_MARKED, false, true);
    if (ctx.error) {
        expBufFree(&ctx.buf);
        return NULL;
    }
    char *result = bufToPlainString(&ctx.buf);
    expBufFree(&ctx.buf);
    return result;
}

char *shExpandHereDocument(ShInterp *interp, const char *body) {
    if (!body) {
        return strdup("");
    }
    ExpCtx ctx = {interp, {0}, false, false};
    expandText(&ctx, body, strlen(body), MODE_HEREDOC, false, false);
    char *result = bufToPlainString(&ctx.buf);
    expBufFree(&ctx.buf);
    if (ctx.error) {
        free(result);
        return NULL;
    }
    return result;
}

char *shExpandPattern(ShInterp *interp, const ShellWord *word) {
    if (!word || !word->text) {
        return strdup("");
    }
    ExpCtx ctx = {interp, {0}, false, false};
    expandText(&ctx, word->text, strlen(word->text), MODE_MARKED, false, false);
    if (ctx.error) {
        expBufFree(&ctx.buf);
        return NULL;
    }
    char *pattern = bufToGlobPattern(&ctx.buf);
    expBufFree(&ctx.buf);
    return pattern;
}

bool shPatternMatch(const char *pattern, const char *string) {
    if (!pattern || !string) {
        return false;
    }
    return fnmatch(pattern, string, 0) == 0;
}
