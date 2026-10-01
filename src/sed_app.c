/*
 * sed: a POSIX stream editor with the GNU extensions Linux scripts rely on.
 *
 * This replaces a substitution-only sed (s, y, d, p; g and i flags), which
 * quietly broke scripts as soon as it shadowed a distro's GNU sed -- iSH-AOK's
 * native-links.sh puts SmallCLUE's applets ahead of /usr/bin, maintainer
 * scripts included. `sed -n 's/x/y/p'` was rejected outright, and `sed -i`
 * rewrote files 0600.
 *
 * Commands: {} = a b c d D F g G h H i l n N p P q Q r R s t T v w W x y z :
 * and #, with GNU's one-line a/i/c forms. Addresses: N, $, /re/ and \cREc
 * (with I and M), first~step, addr,+N, addr,~N, 0,/re/, and !. s flags: g, p,
 * N, w FILE, i/I, m/M; the replacement takes &, \0-\9, \n, \t and GNU's
 * \L \U \l \u \E. Regexes take \n and \t, and GNU's \+ \? \| in basic syntax
 * (REG_ENHANCED on Darwin; glibc has them natively). Options: -n -e -f -E -r
 * -i[SUFFIX] -s -z -u -l N --posix --follow-symlinks and the long forms.
 *
 * Behaviour follows GNU sed 4.9 where POSIX leaves room: N and n on the last
 * line print the pattern space, -i and -s restart line numbers and ranges per
 * file, a missing final newline is kept, and `sed -i` keeps the file's mode
 * and owner.
 *
 * Runs as a function call in hosts that embed SmallCLUE (iSH-AOK), so there is
 * no global state and every path frees what it allocated and closes what it
 * opened.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* realpath, strndup under a strict -std= */
#endif
#include "sed_app.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------------------------------------------------ */
/* Growable byte buffer                                                      */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} SedBuf;

static bool sedBufReserve(SedBuf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return true;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < b->len + extra + 1) cap *= 2;
    char *d = (char *)realloc(b->data, cap);
    if (!d) return false;
    b->data = d;
    b->cap = cap;
    return true;
}

static bool sedBufAppend(SedBuf *b, const char *s, size_t n) {
    if (!sedBufReserve(b, n)) return false;
    if (n) memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return true;
}

static bool sedBufAppendChar(SedBuf *b, char c) {
    return sedBufAppend(b, &c, 1);
}

static bool sedBufSet(SedBuf *b, const char *s, size_t n) {
    b->len = 0;
    return sedBufAppend(b, s, n);
}

static void sedBufFree(SedBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ------------------------------------------------------------------------ */
/* Compiled script                                                           */

typedef enum {
    SED_A_NONE,
    SED_A_LINE,  /* n */
    SED_A_LAST,  /* $ */
    SED_A_RE,    /* /re/ */
    SED_A_ZERO,  /* 0, only as the first half of 0,/re/ */
    SED_A_STEP,  /* first~step */
    SED_A_PLUS,  /* second address +N */
    SED_A_MULT,  /* second address ~N */
} SedAddrType;

typedef struct {
    SedAddrType type;
    long n1;
    long n2;
    regex_t *re; /* NULL with type SED_A_RE: the last regex used */
} SedAddr;

typedef enum { SED_R_LIT, SED_R_GROUP, SED_R_CASE } SedReplKind;

typedef enum {
    SED_CASE_NONE,
    SED_CASE_UPPER,     /* \U */
    SED_CASE_LOWER,     /* \L */
    SED_CASE_UPPER1,    /* \u */
    SED_CASE_LOWER1,    /* \l */
    SED_CASE_END,       /* \E */
} SedCase;

typedef struct {
    SedReplKind kind;
    char *text;
    size_t len;
    int group;
    SedCase caseOp;
} SedReplPart;

typedef struct SedOutput {
    FILE *fp;
    bool missingNewline;
    bool owned;
    char *name;
} SedOutput;

typedef struct {
    char *name;
    FILE *fp;
    bool eof;
} SedReadFile;

typedef struct {
    char cmd;
    SedAddr a1;
    SedAddr a2;
    int naddr;
    bool negate;
    /* range state */
    bool rangeActive;
    long rangeEnd;
    bool rangeEnded; /* set by the match that closed the range */

    /* arguments */
    char *text;     /* a i c: the text, ending in '\n' */
    size_t textLen;
    char *label;    /* : b t T */
    int target;     /* b t T: command index, or ncmds for end of script; {: its } */
    long intArg;    /* q Q l L */
    bool haveInt;
    int outIdx;     /* w W, s///w: index into outputs, -1 none */
    int rfileIdx;   /* R: index into rfiles */
    char *fileName; /* r; e: the command, "" for none */

    /* s */
    regex_t *re;
    SedReplPart *parts;
    size_t nparts;
    bool global;
    long occurrence;
    int printCount;
    bool eval;      /* s///e */
    int printPre;   /* p flags written before e: they print before it runs */

    /* y */
    unsigned char ymap[256];
} SedCmd;

typedef struct {
    SedCmd *cmds;
    size_t ncmds;
    size_t cap;
    regex_t **regexes; /* every regex compiled, for freeing */
    size_t nregexes;
    SedOutput **outputs;
    size_t noutputs;
    SedReadFile *rfiles;
    size_t nrfiles;
    bool extended;
    bool quietFromScript; /* #n on the first line */
    char delim;
    bool posix;
    int exitStatus; /* for a script that fails after parsing, as GNU's 4 */
} SedProgram;

/* ------------------------------------------------------------------------ */
/* Input                                                                     */

typedef struct {
    char **files;
    int nfiles;
    int next;         /* index of the next file to open */
    FILE *fp;
    bool fpIsStdin;
    const char *fpName;
    int pushback;     /* a character read ahead by the EOF test, or -1 */
    char delim;
    int *status;
    bool stdinUsed;
} SedInput;

typedef struct {
    SedProgram *prog;
    SedInput *in;
    SedOutput *out;     /* where the pattern space goes */
    SedOutput *stdoutOut;
    SedBuf ps;
    SedBuf hs;
    SedBuf appendQ;
    bool chomped;       /* the current line had its delimiter */
    long lineNo;
    const char *lineName; /* file the current line came from */
    bool quiet;
    bool unbuffered;
    bool tflag;
    bool quit;
    int exitCode;
    bool quitRequested;
    regex_t *lastRe;
    long lineWrap;
    int status;
} SedRun;

static int sedGetc(SedInput *in) {
    if (in->pushback >= 0) {
        int c = in->pushback;
        in->pushback = -1;
        return c;
    }
#if defined(PSCAL_TARGET_IOS)
    if (in->fpIsStdin) {
        int err = 0;
        return smallclueSedStdinGetc(&err);
    }
#endif
    return getc(in->fp);
}

static void sedCloseCurrent(SedInput *in) {
    if (in->fp && !in->fpIsStdin) fclose(in->fp);
    in->fp = NULL;
    in->fpIsStdin = false;
    in->pushback = -1;
}

/* Opens the next readable file. False when none is left. */
static bool sedOpenNext(SedInput *in) {
    while (in->next < in->nfiles) {
        const char *name = in->files[in->next++];
        if (strcmp(name, "-") == 0) {
            in->fp = stdin;
            in->fpIsStdin = true;
            in->fpName = "-";
            in->pushback = -1;
            return true;
        }
        FILE *fp = fopen(name, "r");
        if (!fp) {
            fprintf(stderr, "sed: can't read %s: %s\n", name, strerror(errno));
            *in->status = 2;
            continue;
        }
        struct stat st;
        if (fstat(fileno(fp), &st) == 0 && S_ISDIR(st.st_mode)) {
            fprintf(stderr, "sed: couldn't edit %s: not a regular file\n", name);
            fclose(fp);
            *in->status = 2;
            continue;
        }
        in->fp = fp;
        in->fpIsStdin = false;
        in->fpName = name;
        in->pushback = -1;
        return true;
    }
    return false;
}

/* True when no input is left. Reads one character ahead, so it is only asked
 * when a command needs to know ($, n, N): a plain `sed s/a/b/` on a terminal
 * still answers each line as it arrives. */
static bool sedAtEof(SedInput *in) {
    for (;;) {
        if (!in->fp && !sedOpenNext(in)) return true;
        int c = sedGetc(in);
        if (c != EOF) {
            in->pushback = c;
            return false;
        }
        sedCloseCurrent(in);
    }
}

/* Reads one line into `line` without its delimiter. */
static bool sedReadLine(SedInput *in, SedBuf *line, bool *chomped, const char **name) {
    for (;;) {
        if (!in->fp && !sedOpenNext(in)) return false;
        line->len = 0;
        if (!sedBufReserve(line, 0)) return false;
        line->data[0] = '\0';
        int c = sedGetc(in);
        if (c == EOF) {
            sedCloseCurrent(in);
            continue;
        }
        bool gotDelim = false;
        while (c != EOF) {
            if (c == (unsigned char)in->delim) {
                gotDelim = true;
                break;
            }
            if (!sedBufAppendChar(line, (char)c)) return false;
            c = sedGetc(in);
        }
        *chomped = gotDelim;
        *name = in->fpName;
        return true;
    }
}

/* ------------------------------------------------------------------------ */
/* Output                                                                    */

static void sedOutFlushMissing(SedOutput *o, char delim) {
    if (o->missingNewline) {
        putc(delim, o->fp);
        o->missingNewline = false;
    }
}

/* Writes pattern-space text: the delimiter follows unless the input line
 * lacked one, in which case it is owed before anything else is written. */
static void sedOutPattern(SedRun *r, SedOutput *o, const char *s, size_t n, bool addDelim) {
    char delim = r->prog->delim;
    sedOutFlushMissing(o, delim);
    fwrite(s, 1, n, o->fp);
    if (addDelim)
        putc(delim, o->fp);
    else
        o->missingNewline = true;
    if (r->unbuffered) fflush(o->fp);
}

static void sedOutText(SedRun *r, SedOutput *o, const char *s, size_t n) {
    sedOutFlushMissing(o, r->prog->delim);
    fwrite(s, 1, n, o->fp);
    if (r->unbuffered) fflush(o->fp);
}

static void sedFlushAppend(SedRun *r) {
    if (r->appendQ.len) {
        sedOutText(r, r->out, r->appendQ.data, r->appendQ.len);
        r->appendQ.len = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* Parser                                                                    */

typedef struct {
    const char *s;
    size_t pos;
    size_t len;
    SedProgram *prog;
    SedOutput *stdoutOut;
    char *err;
    size_t errCap;
    bool failed;
} SedParser;

static void sedParseError(SedParser *p, const char *fmt, ...) {
    if (p->failed) return;
    p->failed = true;
    va_list ap;
    va_start(ap, fmt);
    char msg[256];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fprintf(stderr, "sed: -e expression #1, char %zu: %s\n", p->pos, msg);
}

static int sedPeek(SedParser *p) {
    return p->pos < p->len ? (unsigned char)p->s[p->pos] : EOF;
}

static void sedSkipSpace(SedParser *p) {
    while (p->pos < p->len && (p->s[p->pos] == ' ' || p->s[p->pos] == '\t')) p->pos++;
}

static bool sedParseNumber(SedParser *p, long *out) {
    if (p->pos >= p->len || !isdigit((unsigned char)p->s[p->pos])) return false;
    long v = 0;
    while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos])) {
        v = v * 10 + (p->s[p->pos] - '0');
        p->pos++;
    }
    *out = v;
    return true;
}

static regex_t *sedRegisterRegex(SedProgram *prog, regex_t *re) {
    regex_t **n = (regex_t **)realloc(prog->regexes, (prog->nregexes + 1) * sizeof(*n));
    if (!n) {
        regfree(re);
        free(re);
        return NULL;
    }
    prog->regexes = n;
    prog->regexes[prog->nregexes++] = re;
    return re;
}

/* GNU's numeric and control escapes: \xHH, \dNNN, \oNNN, \cX. `src` points
 * at the letter after the backslash; returns how many bytes it used (0 when
 * this is not one of them) and the byte in *out. */
static size_t sedNumericEscape(const char *src, size_t n, unsigned char *out) {
    if (n < 2) return 0;
    char kind = src[0];
    int base = kind == 'x' ? 16 : kind == 'd' ? 10 : kind == 'o' ? 8 : 0;
    if (kind == 'c') {
        *out = (unsigned char)(toupper((unsigned char)src[1]) ^ 0x40);
        return 2;
    }
    if (!base) return 0;
    size_t maxDigits = kind == 'x' ? 2 : 3;
    size_t i = 1;
    int v = 0;
    while (i < n && i <= maxDigits) {
        int c = (unsigned char)src[i], d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        if (d >= base) break;
        v = v * base + d;
        i++;
    }
    if (i == 1) return 0;
    *out = (unsigned char)v;
    return i;
}

/* Converts sed's regex spelling into regcomp's: \n and \t become the
 * characters (inside brackets too, as GNU does), everything else passes
 * through. The delimiter escape has already been removed by the scanner. */
static char *sedTranslateRegex(const char *src, size_t n) {
    SedBuf b = {0};
    if (!sedBufReserve(&b, n)) return NULL;
    for (size_t i = 0; i < n; i++) {
        char c = src[i];
        if (c == '\\' && i + 1 < n) {
            char d = src[i + 1];
            if (d == 'n') { sedBufAppendChar(&b, '\n'); i++; continue; }
            if (d == 't') { sedBufAppendChar(&b, '\t'); i++; continue; }
            unsigned char v;
            size_t used = sedNumericEscape(src + i + 1, n - i - 1, &v);
            if (used) {
                /* As in GNU sed 4.9, the byte keeps any special meaning:
                 * s/\x2e/!/ matches any character, not only a dot. */
                sedBufAppendChar(&b, (char)v);
                i += used;
                continue;
            }
            sedBufAppendChar(&b, c);
            sedBufAppendChar(&b, d);
            i++;
            continue;
        }
        sedBufAppendChar(&b, c);
    }
    return b.data;
}

static regex_t *sedCompile(SedParser *p, const char *pat, size_t n, bool icase, bool multiline, bool *emptyOut) {
    *emptyOut = (n == 0);
    if (n == 0) return NULL;
    char *text = sedTranslateRegex(pat, n);
    if (!text) {
        sedParseError(p, "out of memory");
        return NULL;
    }
    int flags = 0;
    if (p->prog->extended) flags |= REG_EXTENDED;
    if (icase) flags |= REG_ICASE;
    if (multiline) flags |= REG_NEWLINE;
#ifdef REG_ENHANCED
    if (!p->prog->posix) flags |= REG_ENHANCED;
#endif
    regex_t *re = (regex_t *)calloc(1, sizeof(*re));
    if (!re) {
        free(text);
        sedParseError(p, "out of memory");
        return NULL;
    }
    int rc = regcomp(re, text, flags);
    free(text);
    if (rc != 0) {
        char msg[200];
        regerror(rc, re, msg, sizeof(msg));
        free(re);
        sedParseError(p, "%s", msg);
        return NULL;
    }
    return sedRegisterRegex(p->prog, re);
}

/* Scans a regex up to the unescaped delimiter, starting just past the
 * opening one. A bracket expression is copied whole: the delimiter needs no
 * escape inside one. `\delim` becomes the delimiter itself. */
static bool sedScanRegex(SedParser *p, char delim, SedBuf *out) {
    out->len = 0;
    sedBufReserve(out, 0);
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == delim) {
            p->pos++;
            return true;
        }
        if (c == '\\') {
            if (p->pos + 1 >= p->len) break;
            char d = p->s[p->pos + 1];
            if (d == delim) {
                sedBufAppendChar(out, delim);
            } else if (d == '\n') {
                sedBufAppendChar(out, '\\');
                sedBufAppendChar(out, 'n');
            } else {
                sedBufAppendChar(out, '\\');
                sedBufAppendChar(out, d);
            }
            p->pos += 2;
            continue;
        }
        if (c == '\n' && delim != '\n') {
            break;
        }
        if (c == '[') {
            size_t start = p->pos;
            size_t i = p->pos + 1;
            if (i < p->len && p->s[i] == '^') i++;
            if (i < p->len && p->s[i] == ']') i++;
            while (i < p->len && p->s[i] != ']') {
                if (p->s[i] == '[' && i + 1 < p->len &&
                    (p->s[i + 1] == ':' || p->s[i + 1] == '.' || p->s[i + 1] == '=')) {
                    char kind = p->s[i + 1];
                    size_t j = i + 2;
                    while (j + 1 < p->len && !(p->s[j] == kind && p->s[j + 1] == ']')) j++;
                    i = j + 2;
                    continue;
                }
                if (p->s[i] == '\n') break;
                i++;
            }
            if (i < p->len && p->s[i] == ']') {
                sedBufAppend(out, p->s + start, i + 1 - start);
                p->pos = i + 1;
                continue;
            }
            /* No closing bracket: let regcomp report it. */
        }
        sedBufAppendChar(out, c);
        p->pos++;
    }
    sedParseError(p, "unterminated address regex");
    return false;
}

static bool sedParseRegexFlags(SedParser *p, bool *icase, bool *multiline) {
    *icase = false;
    *multiline = false;
    for (;;) {
        int c = sedPeek(p);
        if (c == 'I') { *icase = true; p->pos++; continue; }
        if (c == 'M') { *multiline = true; p->pos++; continue; }
        return true;
    }
}

static bool sedParseAddr(SedParser *p, SedAddr *a, bool second) {
    int c = sedPeek(p);
    a->type = SED_A_NONE;
    if (c == '$') {
        p->pos++;
        a->type = SED_A_LAST;
        return true;
    }
    if (second && (c == '+' || c == '~')) {
        p->pos++;
        long n = 0;
        if (!sedParseNumber(p, &n)) {
            sedParseError(p, "expected number after %c", c);
            return false;
        }
        a->type = (c == '+') ? SED_A_PLUS : SED_A_MULT;
        a->n1 = n;
        return true;
    }
    if (c != EOF && isdigit(c)) {
        long n = 0;
        sedParseNumber(p, &n);
        if (!second && sedPeek(p) == '~') {
            p->pos++;
            long step = 0;
            if (!sedParseNumber(p, &step)) {
                sedParseError(p, "expected number after ~");
                return false;
            }
            a->type = SED_A_STEP;
            a->n1 = n;
            a->n2 = step;
            return true;
        }
        if (n == 0 && !second) {
            a->type = SED_A_ZERO;
            return true;
        }
        a->type = SED_A_LINE;
        a->n1 = n;
        return true;
    }
    if (c == '/' || c == '\\') {
        char delim = '/';
        p->pos++;
        if (c == '\\') {
            if (p->pos >= p->len) {
                sedParseError(p, "unexpected end of expression");
                return false;
            }
            delim = p->s[p->pos++];
        }
        SedBuf pat = {0};
        if (!sedScanRegex(p, delim, &pat)) {
            sedBufFree(&pat);
            return false;
        }
        bool icase, ml, empty;
        sedParseRegexFlags(p, &icase, &ml);
        a->type = SED_A_RE;
        a->re = sedCompile(p, pat.data, pat.len, icase, ml, &empty);
        sedBufFree(&pat);
        if (!empty && !a->re) return false;
        return true;
    }
    return true;
}

/* End of a command: spaces, then ; or newline or # or } or the end. */
static bool sedEndCommand(SedParser *p, char cmd) {
    sedSkipSpace(p);
    int c = sedPeek(p);
    if (c == EOF || c == '}' || c == '#') return true;
    if (c == ';' || c == '\n') {
        p->pos++;
        return true;
    }
    (void)cmd;
    p->pos++;   /* GNU counts the offending character */
    sedParseError(p, "extra characters after command");
    return false;
}

/* Rest of the line, for file names. */
static char *sedReadToEol(SedParser *p) {
    sedSkipSpace(p);
    size_t start = p->pos;
    while (p->pos < p->len && p->s[p->pos] != '\n') p->pos++;
    char *s = strndup(p->s + start, p->pos - start);
    if (p->pos < p->len) p->pos++;
    return s;
}

/* The file name of r R w W and s///w; NULL, after GNU's message, when none. */
static char *sedReadFileName(SedParser *p) {
    sedSkipSpace(p);
    if (p->pos >= p->len || p->s[p->pos] == '\n') {
        sedParseError(p, "missing filename in r/R/w/W commands");
        return NULL;
    }
    return sedReadToEol(p);
}

/* A label: up to ; or newline, trailing blanks dropped. */
static char *sedReadLabel(SedParser *p) {
    sedSkipSpace(p);
    size_t start = p->pos;
    while (p->pos < p->len && p->s[p->pos] != '\n' && p->s[p->pos] != ';') p->pos++;
    size_t end = p->pos;
    while (end > start && (p->s[end - 1] == ' ' || p->s[end - 1] == '\t')) end--;
    char *s = strndup(p->s + start, end - start);
    if (p->pos < p->len) p->pos++;
    return s;
}

/* The text of a, i or c. `a\` newline TEXT is POSIX; `a TEXT` and `a\TEXT`
 * are GNU's one-line forms. A backslash at the end of a line continues the
 * text; a backslash before any other character yields that character. */
static bool sedReadText(SedParser *p, SedCmd *cmd) {
    SedBuf t = {0};
    sedSkipSpace(p);
    if (sedPeek(p) == '\\') {
        /* a\ newline TEXT, or GNU's a\TEXT: leading blanks are kept. */
        p->pos++;
        if (sedPeek(p) == '\n') p->pos++;
    }
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == '\\') {
            if (p->pos + 1 < p->len) {
                char d = p->s[p->pos + 1];
                if (d == '\n')
                    sedBufAppendChar(&t, '\n');
                else if (d == 't' && !p->prog->posix)
                    sedBufAppendChar(&t, '\t');
                else
                    sedBufAppendChar(&t, d);
                p->pos += 2;
            } else {
                p->pos++;
            }
            continue;
        }
        if (c == '\n') {
            p->pos++;
            break;
        }
        sedBufAppendChar(&t, c);
        p->pos++;
    }
    sedBufAppendChar(&t, '\n');
    cmd->text = t.data;
    cmd->textLen = t.len;
    return true;
}

static int sedFindOutput(SedParser *p, const char *name) {
    SedProgram *prog = p->prog;
    for (size_t i = 0; i < prog->noutputs; i++) {
        if (strcmp(prog->outputs[i]->name, name) == 0) return (int)i;
    }
    SedOutput *o = (SedOutput *)calloc(1, sizeof(*o));
    if (!o) return -1;
    o->name = strdup(name);
    if (strcmp(name, "/dev/stdout") == 0) {
        o->fp = NULL; /* resolved to the run's stdout at execution */
    } else if (strcmp(name, "/dev/stderr") == 0) {
        o->fp = stderr;
    } else {
        o->fp = fopen(name, "w");
        if (!o->fp) {
            fprintf(stderr, "sed: couldn't open file %s: %s\n", name, strerror(errno));
            free(o->name);
            free(o);
            p->failed = true;
            return -1;
        }
        o->owned = true;
    }
    SedOutput **n = (SedOutput **)realloc(prog->outputs, (prog->noutputs + 1) * sizeof(*n));
    if (!n) {
        if (o->owned) fclose(o->fp);
        free(o->name);
        free(o);
        return -1;
    }
    prog->outputs = n;
    prog->outputs[prog->noutputs] = o;
    return (int)prog->noutputs++;
}

static int sedFindRFile(SedProgram *prog, const char *name) {
    for (size_t i = 0; i < prog->nrfiles; i++) {
        if (strcmp(prog->rfiles[i].name, name) == 0) return (int)i;
    }
    SedReadFile *n = (SedReadFile *)realloc(prog->rfiles, (prog->nrfiles + 1) * sizeof(*n));
    if (!n) return -1;
    prog->rfiles = n;
    prog->rfiles[prog->nrfiles].name = strdup(name);
    prog->rfiles[prog->nrfiles].fp = NULL;
    prog->rfiles[prog->nrfiles].eof = false;
    return (int)prog->nrfiles++;
}

static bool sedAddPart(SedCmd *cmd, SedReplPart part) {
    SedReplPart *n = (SedReplPart *)realloc(cmd->parts, (cmd->nparts + 1) * sizeof(*n));
    if (!n) return false;
    cmd->parts = n;
    cmd->parts[cmd->nparts++] = part;
    return true;
}

static void sedFlushLiteral(SedCmd *cmd, SedBuf *lit) {
    if (lit->len == 0) return;
    SedReplPart part = {SED_R_LIT, strndup(lit->data, lit->len), lit->len, 0, SED_CASE_NONE};
    sedAddPart(cmd, part);
    lit->len = 0;
}

static bool sedParseReplacement(SedParser *p, char delim, SedCmd *cmd) {
    SedBuf lit = {0};
    sedBufReserve(&lit, 0);
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == delim) {
            p->pos++;
            sedFlushLiteral(cmd, &lit);
            sedBufFree(&lit);
            return true;
        }
        if (c == '\\' && p->pos + 1 < p->len) {
            char d = p->s[p->pos + 1];
            unsigned char byte;
            size_t used;
            p->pos += 2;
            if (d == delim) {
                sedBufAppendChar(&lit, d);
            } else if (d >= '0' && d <= '9') {
                sedFlushLiteral(cmd, &lit);
                SedReplPart part = {SED_R_GROUP, NULL, 0, d - '0', SED_CASE_NONE};
                sedAddPart(cmd, part);
            } else if (d == 'n') {
                sedBufAppendChar(&lit, '\n');
            } else if (d == 't') {
                sedBufAppendChar(&lit, '\t');
            } else if ((used = sedNumericEscape(p->s + p->pos - 1, p->len - p->pos + 1, &byte)) != 0) {
                sedBufAppendChar(&lit, (char)byte);
                p->pos += used - 1;
            } else if (d == '\n') {
                sedBufAppendChar(&lit, '\n');
            } else if (!p->prog->posix && (d == 'U' || d == 'L' || d == 'u' || d == 'l' || d == 'E')) {
                sedFlushLiteral(cmd, &lit);
                SedCase op = d == 'U' ? SED_CASE_UPPER : d == 'L' ? SED_CASE_LOWER
                           : d == 'u' ? SED_CASE_UPPER1 : d == 'l' ? SED_CASE_LOWER1 : SED_CASE_END;
                SedReplPart part = {SED_R_CASE, NULL, 0, 0, op};
                sedAddPart(cmd, part);
            } else {
                sedBufAppendChar(&lit, d);
            }
            continue;
        }
        if (c == '&') {
            sedFlushLiteral(cmd, &lit);
            SedReplPart part = {SED_R_GROUP, NULL, 0, 0, SED_CASE_NONE};
            sedAddPart(cmd, part);
            p->pos++;
            continue;
        }
        if (c == '\n' && delim != '\n') {
            break;
        }
        sedBufAppendChar(&lit, c);
        p->pos++;
    }
    sedBufFree(&lit);
    sedParseError(p, "unterminated `s' command");
    return false;
}

static bool sedParseS(SedParser *p, SedCmd *cmd) {
    if (p->pos >= p->len || p->s[p->pos] == '\n' || p->s[p->pos] == '\\') {
        sedParseError(p, "unterminated `s' command");
        return false;
    }
    char delim = p->s[p->pos++];
    SedBuf pat = {0};
    if (!sedScanRegex(p, delim, &pat)) {
        sedBufFree(&pat);
        return false;
    }
    if (!sedParseReplacement(p, delim, cmd)) {
        sedBufFree(&pat);
        return false;
    }
    bool icase = false, ml = false;
    cmd->occurrence = 0;
    for (;;) {
        int c = sedPeek(p);
        const char *excess = NULL;
        if (c == 'g') { excess = cmd->global ? "multiple `g' options to `s' command" : NULL; cmd->global = true; p->pos++; }
        else if (c == 'p') {
            excess = cmd->printCount + cmd->printPre ? "multiple `p' options to `s' command" : NULL;
            if (cmd->eval) cmd->printCount++; else cmd->printPre++;
            p->pos++;
        }
        else if (c == 'i' || c == 'I') { icase = true; p->pos++; }
        else if (c == 'm' || c == 'M') { ml = true; p->pos++; }
        else if (c != EOF && isdigit(c)) {
            long n = 0;
            sedParseNumber(p, &n);
            if (n == 0) {
                sedBufFree(&pat);
                sedParseError(p, "number option to `s' command may not be zero");
                return false;
            }
            if (cmd->occurrence) excess = "multiple number options to `s' command";
            cmd->occurrence = n;
        } else if (c == 'w') {
            p->pos++;
            char *name = sedReadFileName(p);
            cmd->outIdx = name ? sedFindOutput(p, name) : -1;
            free(name);
            if (cmd->outIdx < 0) {
                sedBufFree(&pat);
                return false;
            }
            break;
        } else if (c == 'e' && !p->prog->posix) {
            cmd->eval = true;
            p->pos++;
        } else if (c == ' ' || c == '\t') {
            p->pos++;
        } else if (c == EOF || c == ';' || c == '\n' || c == '}' || c == '#') {
            break;
        } else {
            p->pos++;
            sedBufFree(&pat);
            sedParseError(p, "unknown option to `s'");
            return false;
        }
        if (excess) {
            sedBufFree(&pat);
            sedParseError(p, "%s", excess);
            return false;
        }
    }
    if (cmd->occurrence == 0) cmd->occurrence = 1;
    bool empty = false;
    cmd->re = sedCompile(p, pat.data, pat.len, icase, ml, &empty);
    sedBufFree(&pat);
    if (!empty && !cmd->re) return false;
    if (cmd->re) {
        for (size_t i = 0; i < cmd->nparts; i++) {
            if (cmd->parts[i].kind == SED_R_GROUP && (size_t)cmd->parts[i].group > cmd->re->re_nsub) {
                sedParseError(p, "invalid reference \\%d on `s' command's RHS", cmd->parts[i].group);
                return false;
            }
        }
    }
    if (cmd->outIdx >= 0) return true; /* w consumed the line */
    return sedEndCommand(p, 's');
}

/* y/SRC/DST/: \delim, \\ and \n are the escapes. */
static bool sedParseY(SedParser *p, SedCmd *cmd) {
    if (p->pos >= p->len) {
        sedParseError(p, "unterminated `y' command");
        return false;
    }
    char delim = p->s[p->pos++];
    SedBuf sets[2] = {{0}, {0}};
    for (int k = 0; k < 2; k++) {
        sedBufReserve(&sets[k], 0);
        bool closed = false;
        while (p->pos < p->len) {
            char c = p->s[p->pos];
            if (c == delim) { p->pos++; closed = true; break; }
            if (c == '\\' && p->pos + 1 < p->len) {
                char d = p->s[p->pos + 1];
                p->pos += 2;
                if (d == 'n') sedBufAppendChar(&sets[k], '\n');
                else if (d == 't') sedBufAppendChar(&sets[k], '\t');
                else if (d == delim || d == '\\') sedBufAppendChar(&sets[k], d);
                else { sedBufAppendChar(&sets[k], '\\'); sedBufAppendChar(&sets[k], d); }
                continue;
            }
            sedBufAppendChar(&sets[k], c);
            p->pos++;
        }
        if (!closed) {
            sedBufFree(&sets[0]);
            sedBufFree(&sets[1]);
            sedParseError(p, "unterminated `y' command");
            return false;
        }
    }
    if (sets[0].len != sets[1].len) {
        sedBufFree(&sets[0]);
        sedBufFree(&sets[1]);
        sedParseError(p, "strings for `y' command are different lengths");
        return false;
    }
    for (int i = 0; i < 256; i++) cmd->ymap[i] = (unsigned char)i;
    for (size_t i = 0; i < sets[0].len; i++)
        cmd->ymap[(unsigned char)sets[0].data[i]] = (unsigned char)sets[1].data[i];
    sedBufFree(&sets[0]);
    sedBufFree(&sets[1]);
    return sedEndCommand(p, 'y');
}

static SedCmd *sedNewCmd(SedProgram *prog) {
    if (prog->ncmds == prog->cap) {
        size_t cap = prog->cap ? prog->cap * 2 : 16;
        SedCmd *n = (SedCmd *)realloc(prog->cmds, cap * sizeof(*n));
        if (!n) return NULL;
        prog->cmds = n;
        prog->cap = cap;
    }
    SedCmd *c = &prog->cmds[prog->ncmds++];
    memset(c, 0, sizeof(*c));
    c->outIdx = -1;
    c->rfileIdx = -1;
    c->target = -1;
    return c;
}

static bool sedParseScript(SedProgram *prog, const char *script, size_t len) {
    SedParser p = {script, 0, len, prog, NULL, NULL, 0, false};
    size_t *stack = NULL;
    size_t depth = 0, stackCap = 0;

    if (len >= 2 && script[0] == '#' && script[1] == 'n' && (len == 2 || script[2] == '\n'))
        prog->quietFromScript = true;

    while (!p.failed) {
        while (p.pos < p.len && (isspace((unsigned char)p.s[p.pos]) || p.s[p.pos] == ';')) p.pos++;
        if (p.pos >= p.len) break;
        if (p.s[p.pos] == '#') {
            while (p.pos < p.len && p.s[p.pos] != '\n') p.pos++;
            continue;
        }
        SedCmd *cmd = sedNewCmd(prog);
        if (!cmd) { sedParseError(&p, "out of memory"); break; }
        size_t cmdIndex = prog->ncmds - 1;

        if (!sedParseAddr(&p, &cmd->a1, false)) break;
        if (cmd->a1.type != SED_A_NONE) {
            cmd->naddr = 1;
            sedSkipSpace(&p);
            if (sedPeek(&p) == ',') {
                p.pos++;
                sedSkipSpace(&p);
                if (!sedParseAddr(&p, &cmd->a2, true)) break;
                if (cmd->a2.type == SED_A_NONE) {
                    sedParseError(&p, "unexpected `,'");
                    break;
                }
                cmd->naddr = 2;
            }
        }
        if (cmd->a1.type == SED_A_ZERO && (cmd->naddr != 2 || cmd->a2.type != SED_A_RE)) {
            sedParseError(&p, "invalid usage of line address 0");
            break;
        }
        sedSkipSpace(&p);
        while (sedPeek(&p) == '!') {
            cmd->negate = true;
            p.pos++;
            sedSkipSpace(&p);
        }
        int c = sedPeek(&p);
        if (c == EOF) {
            sedParseError(&p, "missing command");
            break;
        }
        cmd->cmd = (char)c;
        p.pos++;
        switch (c) {
            case '{':
                if (depth == stackCap) {
                    stackCap = stackCap ? stackCap * 2 : 8;
                    size_t *n = (size_t *)realloc(stack, stackCap * sizeof(*n));
                    if (!n) { sedParseError(&p, "out of memory"); break; }
                    stack = n;
                }
                stack[depth++] = cmdIndex;
                break;
            case '}':
                if (cmd->naddr) { sedParseError(&p, "} doesn't want any addresses"); break; }
                if (depth == 0) { sedParseError(&p, "unexpected `}'"); break; }
                prog->cmds[stack[--depth]].target = (int)cmdIndex;
                sedEndCommand(&p, '}');
                break;
            case '=': case 'd': case 'D': case 'F': case 'g': case 'G': case 'h': case 'H':
            case 'n': case 'N': case 'p': case 'P': case 'x': case 'z':
                sedEndCommand(&p, (char)c);
                break;
            case 'a': case 'i': case 'c':
                sedReadText(&p, cmd);
                break;
            case ':':
                if (cmd->naddr) { sedParseError(&p, ": doesn't want any addresses"); break; }
                cmd->label = sedReadLabel(&p);
                if (!cmd->label || !*cmd->label) sedParseError(&p, "\":\" lacks a label");
                break;
            case 'b': case 't': case 'T':
                cmd->label = sedReadLabel(&p);
                break;
            case 'l': case 'L': case 'q': case 'Q':
                sedSkipSpace(&p);
                if (sedParseNumber(&p, &cmd->intArg)) cmd->haveInt = true;
                sedEndCommand(&p, (char)c);
                break;
            case 'r': {
                cmd->fileName = sedReadFileName(&p);
                break;
            }
            case 'R': {
                char *name = sedReadFileName(&p);
                if (!name) break;
                cmd->rfileIdx = sedFindRFile(prog, name);
                free(name);
                break;
            }
            case 'w': case 'W': {
                char *name = sedReadFileName(&p);
                if (!name) break;
                cmd->outIdx = sedFindOutput(&p, name);
                free(name);
                break;
            }
            case 's':
                sedParseS(&p, cmd);
                break;
            case 'y':
                sedParseY(&p, cmd);
                break;
            case 'v':
                free(sedReadLabel(&p));
                break;
            case 'e':
                if (p.prog->posix) {
                    sedParseError(&p, "unknown command: `%c'", c);
                    break;
                }
                cmd->fileName = sedReadToEol(&p);
                break;
            default:
                p.pos--;
                sedParseError(&p, "unknown command: `%c'", c);
                break;
        }
    }
    if (!p.failed && depth > 0) {
        sedParseError(&p, "unmatched `{'");
    }
    free(stack);
    if (p.failed) return false;

    /* Resolve branch targets. */
    for (size_t i = 0; i < prog->ncmds; i++) {
        SedCmd *cmd = &prog->cmds[i];
        if (cmd->cmd != 'b' && cmd->cmd != 't' && cmd->cmd != 'T') continue;
        if (!cmd->label || !*cmd->label) {
            cmd->target = (int)prog->ncmds;
            continue;
        }
        cmd->target = -1;
        for (size_t j = 0; j < prog->ncmds; j++) {
            if (prog->cmds[j].cmd == ':' && strcmp(prog->cmds[j].label, cmd->label) == 0) {
                cmd->target = (int)j;
                break;
            }
        }
        if (cmd->target < 0) {
            fprintf(stderr, "sed: can't find label for jump to `%s'\n", cmd->label);
            prog->exitStatus = 4;
            return false;
        }
    }
    return true;
}

static void sedProgramFree(SedProgram *prog) {
    for (size_t i = 0; i < prog->ncmds; i++) {
        SedCmd *c = &prog->cmds[i];
        free(c->text);
        free(c->label);
        free(c->fileName);
        for (size_t j = 0; j < c->nparts; j++) free(c->parts[j].text);
        free(c->parts);
    }
    free(prog->cmds);
    for (size_t i = 0; i < prog->nregexes; i++) {
        regfree(prog->regexes[i]);
        free(prog->regexes[i]);
    }
    free(prog->regexes);
    for (size_t i = 0; i < prog->noutputs; i++) {
        SedOutput *o = prog->outputs[i];
        if (o->owned && o->fp) fclose(o->fp);
        else if (o->fp) fflush(o->fp);
        free(o->name);
        free(o);
    }
    free(prog->outputs);
    for (size_t i = 0; i < prog->nrfiles; i++) {
        if (prog->rfiles[i].fp) fclose(prog->rfiles[i].fp);
        free(prog->rfiles[i].name);
    }
    free(prog->rfiles);
    memset(prog, 0, sizeof(*prog));
}

/* ------------------------------------------------------------------------ */
/* Execution                                                                 */

static bool sedRegexec(SedRun *r, regex_t *re, const char *s, size_t len, size_t from,
                       regmatch_t *m, size_t nm, bool notbol) {
    regex_t *use = re ? re : r->lastRe;
    if (!use) {
        fprintf(stderr, "sed: no previous regular expression\n");
        r->status = 1;
        r->quit = true;
        return false;
    }
    r->lastRe = use;
    m[0].rm_so = (regoff_t)from;
    m[0].rm_eo = (regoff_t)len;
    int flags = REG_STARTEND | (notbol ? REG_NOTBOL : 0);
    return regexec(use, s, nm, m, flags) == 0;
}

static bool sedMatchOne(SedRun *r, SedAddr *a) {
    switch (a->type) {
        case SED_A_NONE: return true;
        case SED_A_LINE: return r->lineNo == a->n1;
        case SED_A_LAST: return sedAtEof(r->in);
        case SED_A_ZERO: return false;
        case SED_A_STEP:
            if (a->n2 <= 0) return r->lineNo == a->n1;
            return r->lineNo >= a->n1 && (r->lineNo - a->n1) % a->n2 == 0;
        case SED_A_RE: {
            regmatch_t m[1];
            return sedRegexec(r, a->re, r->ps.data, r->ps.len, 0, m, 1, false);
        }
        default: return false;
    }
}

static bool sedMatchAddress(SedRun *r, SedCmd *cmd) {
    cmd->rangeEnded = false;
    bool matched;
    if (cmd->naddr == 0) {
        matched = true;
    } else if (cmd->naddr == 1) {
        matched = sedMatchOne(r, &cmd->a1);
    } else if (cmd->rangeActive) {
        matched = true;
        switch (cmd->a2.type) {
            case SED_A_LINE:
                if (r->lineNo >= cmd->a2.n1) cmd->rangeActive = false;
                break;
            case SED_A_PLUS:
                if (r->lineNo >= cmd->rangeEnd) cmd->rangeActive = false;
                break;
            case SED_A_MULT:
                if (cmd->a2.n1 <= 0 || r->lineNo % cmd->a2.n1 == 0) cmd->rangeActive = false;
                break;
            default:
                if (sedMatchOne(r, &cmd->a2)) cmd->rangeActive = false;
                break;
        }
        if (!cmd->rangeActive) cmd->rangeEnded = true;
    } else if (sedMatchOne(r, &cmd->a1)) {
        matched = true;
        cmd->rangeActive = true;
        switch (cmd->a2.type) {
            case SED_A_LINE:
                if (cmd->a2.n1 <= r->lineNo) cmd->rangeActive = false;
                break;
            case SED_A_PLUS:
                cmd->rangeEnd = r->lineNo + cmd->a2.n1;
                if (cmd->a2.n1 == 0) cmd->rangeActive = false;
                break;
            case SED_A_MULT:
                if (cmd->a2.n1 <= 0 || r->lineNo % cmd->a2.n1 == 0) cmd->rangeActive = false;
                break;
            case SED_A_LAST:
                if (sedAtEof(r->in)) cmd->rangeActive = false;
                break;
            default:
                break; /* a regex end is looked for from the next line */
        }
        if (!cmd->rangeActive) cmd->rangeEnded = true;
    } else {
        matched = false;
    }
    return cmd->negate ? !matched : matched;
}

static void sedResetRanges(SedProgram *prog) {
    for (size_t i = 0; i < prog->ncmds; i++) {
        SedCmd *c = &prog->cmds[i];
        c->rangeActive = (c->naddr == 2 && c->a1.type == SED_A_ZERO);
        c->rangeEnded = false;
    }
}

static void sedAppendCased(SedBuf *out, const char *s, size_t n, SedCase *mode, SedCase *one) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (*one == SED_CASE_UPPER1) { ch = (unsigned char)toupper(ch); *one = SED_CASE_NONE; }
        else if (*one == SED_CASE_LOWER1) { ch = (unsigned char)tolower(ch); *one = SED_CASE_NONE; }
        else if (*mode == SED_CASE_UPPER) ch = (unsigned char)toupper(ch);
        else if (*mode == SED_CASE_LOWER) ch = (unsigned char)tolower(ch);
        sedBufAppendChar(out, (char)ch);
    }
}

static void sedAppendReplacement(SedBuf *out, SedCmd *cmd, const char *s, regmatch_t *m, size_t nsub) {
    SedCase mode = SED_CASE_NONE, one = SED_CASE_NONE;
    for (size_t i = 0; i < cmd->nparts; i++) {
        SedReplPart *part = &cmd->parts[i];
        switch (part->kind) {
            case SED_R_LIT:
                sedAppendCased(out, part->text, part->len, &mode, &one);
                break;
            case SED_R_GROUP: {
                size_t g = (size_t)part->group;
                if (g <= nsub && m[g].rm_so >= 0)
                    sedAppendCased(out, s + m[g].rm_so, (size_t)(m[g].rm_eo - m[g].rm_so), &mode, &one);
                break;
            }
            case SED_R_CASE:
                if (part->caseOp == SED_CASE_UPPER1 || part->caseOp == SED_CASE_LOWER1)
                    one = part->caseOp;
                else if (part->caseOp == SED_CASE_END) {
                    mode = SED_CASE_NONE;
                    one = SED_CASE_NONE;
                } else
                    mode = part->caseOp;
                break;
        }
    }
}

/* GNU's e: what `command` writes, run by /bin/sh. Status 4 when it cannot
 * be started, as GNU's "error in subprocess". */
static bool sedPipeRead(SedRun *r, const char *command, SedBuf *out) {
    sedBufSet(out, "", 0);
    fflush(r->out->fp);
    FILE *fp = popen(command, "r");
    if (!fp) {
        fprintf(stderr, "sed: error in subprocess\n");
        r->exitCode = 4;
        r->quit = true;
        return false;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) sedBufAppend(out, buf, n);
    pclose(fp);
    return true;
}

/* The output of the pattern space run as a command, in its place, less one
 * final delimiter: plain e, and s///e. */
static void sedEvalPattern(SedRun *r) {
    SedBuf res = {0};
    if (!sedPipeRead(r, r->ps.data ? r->ps.data : "", &res)) {
        sedBufFree(&res);
        return;
    }
    if (res.len && res.data[res.len - 1] == r->prog->delim) res.data[--res.len] = '\0';
    sedBufFree(&r->ps);
    r->ps = res;
}

static bool sedSubstitute(SedRun *r, SedCmd *cmd) {
    SedBuf out = {0};
    sedBufReserve(&out, r->ps.len);
    const char *s = r->ps.data;
    size_t len = r->ps.len;
    size_t pos = 0;
    long count = 0;
    bool replaced = false;
    bool havePrev = false;
    size_t prevEnd = 0;
    regmatch_t m[10];

    while (pos <= len) {
        if (!sedRegexec(r, cmd->re, s, len, pos, m, 10, pos > 0)) break;
        size_t so = (size_t)m[0].rm_so, eo = (size_t)m[0].rm_eo;
        if (so == eo && havePrev && so == prevEnd) {
            /* An empty match right where the last one ended is not a match. */
            if (so >= len) break;
            sedBufAppendChar(&out, s[so]);
            pos = so + 1;
            continue;
        }
        count++;
        sedBufAppend(&out, s + pos, so - pos);
        if (count >= cmd->occurrence) {
            size_t nsub = cmd->re ? cmd->re->re_nsub : (r->lastRe ? r->lastRe->re_nsub : 0);
            if (nsub > 9) nsub = 9;
            sedAppendReplacement(&out, cmd, s, m, nsub);
            replaced = true;
        } else {
            sedBufAppend(&out, s + so, eo - so);
        }
        havePrev = true;
        prevEnd = eo;
        if (so == eo) {
            if (so >= len) { pos = len; break; }
            sedBufAppendChar(&out, s[so]);
            pos = so + 1;
        } else {
            pos = eo;
        }
        if (replaced && !cmd->global) break;
    }
    if (r->quit) {
        sedBufFree(&out);
        return false;
    }
    if (!replaced) {
        sedBufFree(&out);
        return false;
    }
    if (pos < len) sedBufAppend(&out, s + pos, len - pos);
    sedBufFree(&r->ps);
    r->ps = out;
    if (!r->ps.data) sedBufSet(&r->ps, "", 0);
    if (cmd->eval) {
        for (int k = 0; k < cmd->printPre; k++) sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
        sedEvalPattern(r);
    }
    return true;
}

static SedOutput *sedResolveOutput(SedRun *r, int idx) {
    SedOutput *o = r->prog->outputs[idx];
    if (!o->fp) return r->stdoutOut;
    return o;
}

/* `l`: the pattern space made unambiguous, wrapped at `width` columns. */
static void sedListLine(SedRun *r, long width) {
    SedBuf b = {0};
    sedBufReserve(&b, r->ps.len * 2);
    size_t col = 0;
    for (size_t i = 0; i < r->ps.len; i++) {
        unsigned char c = (unsigned char)r->ps.data[i];
        char tmp[8];
        const char *e = NULL;
        switch (c) {
            case '\\': e = "\\\\"; break;
            case '\a': e = "\\a"; break;
            case '\b': e = "\\b"; break;
            case '\f': e = "\\f"; break;
            case '\n': e = "\\n"; break;
            case '\r': e = "\\r"; break;
            case '\t': e = "\\t"; break;
            case '\v': e = "\\v"; break;
            default:
                if (c < 0x20 || c >= 0x7f) {
                    snprintf(tmp, sizeof(tmp), "\\%03o", c);
                    e = tmp;
                } else {
                    tmp[0] = (char)c;
                    tmp[1] = '\0';
                    e = tmp;
                }
        }
        size_t elen = strlen(e);
        if (width > 1 && col + elen > (size_t)width - 1) {
            sedBufAppend(&b, "\\\n", 2);
            col = 0;
        }
        sedBufAppend(&b, e, elen);
        col += elen;
    }
    sedBufAppend(&b, "$\n", 2);
    sedOutText(r, r->out, b.data, b.len);
    sedBufFree(&b);
}

static void sedQueueFile(SedRun *r, const char *name) {
    FILE *fp = (strcmp(name, "/dev/stdin") == 0) ? stdin : fopen(name, "r");
    if (!fp) return;
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) sedBufAppend(&r->appendQ, buf, n);
    if (fp != stdin) fclose(fp);
}

static void sedQueueRLine(SedRun *r, SedReadFile *rf) {
    if (rf->eof) return;
    if (!rf->fp) {
        rf->fp = fopen(rf->name, "r");
        if (!rf->fp) {
            rf->eof = true;
            return;
        }
    }
    SedBuf line = {0};
    int c;
    bool any = false;
    while ((c = getc(rf->fp)) != EOF) {
        any = true;
        sedBufAppendChar(&line, (char)c);
        if (c == '\n') break;
    }
    if (!any) {
        rf->eof = true;
    } else {
        if (line.data[line.len - 1] != '\n') sedBufAppendChar(&line, '\n');
        sedBufAppend(&r->appendQ, line.data, line.len);
    }
    sedBufFree(&line);
}

/* Reads the next line into the pattern space (appending after a delimiter
 * when `append`). Appended text is written first, as the cycle it belongs to
 * is over. */
static bool sedReadPattern(SedRun *r, bool append) {
    sedFlushAppend(r);
    SedBuf line = {0};
    bool chomped = false;
    const char *name = NULL;
    if (!sedReadLine(r->in, &line, &chomped, &name)) {
        sedBufFree(&line);
        return false;
    }
    r->lineNo++;
    r->lineName = name;
    r->chomped = chomped;
    if (append) {
        sedBufAppendChar(&r->ps, r->prog->delim);
        sedBufAppend(&r->ps, line.data, line.len);
        sedBufFree(&line);
    } else {
        sedBufFree(&r->ps);
        r->ps = line;
    }
    r->tflag = false;
    return true;
}

typedef enum { SED_END_PRINT, SED_END_NOPRINT, SED_END_QUIT, SED_END_QUIT_SILENT } SedEnd;

/* Runs the script over the current pattern space. */
static SedEnd sedExecute(SedRun *r, bool *restartWithoutRead) {
    SedProgram *prog = r->prog;
    size_t pc = 0;
    *restartWithoutRead = false;
    while (pc < prog->ncmds && !r->quit) {
        SedCmd *cmd = &prog->cmds[pc];
        if (cmd->cmd == ':' || cmd->cmd == '}') {
            pc++;
            continue;
        }
        if (!sedMatchAddress(r, cmd)) {
            if (r->quit) return SED_END_NOPRINT;
            pc = (cmd->cmd == '{') ? (size_t)cmd->target + 1 : pc + 1;
            continue;
        }
        if (r->quit) return SED_END_NOPRINT;
        switch (cmd->cmd) {
            case '{':
                break;
            case '=': {
                char num[32];
                int n = snprintf(num, sizeof(num), "%ld\n", r->lineNo);
                sedOutText(r, r->out, num, (size_t)n);
                break;
            }
            case 'a':
                sedBufAppend(&r->appendQ, cmd->text, cmd->textLen);
                break;
            case 'i':
                sedOutText(r, r->out, cmd->text, cmd->textLen);
                break;
            case 'c':
                if (cmd->naddr < 2 || cmd->negate || cmd->rangeEnded)
                    sedOutText(r, r->out, cmd->text, cmd->textLen);
                return SED_END_NOPRINT;
            case 'b':
                pc = (size_t)cmd->target;
                continue;
            case 't':
                if (r->tflag) {
                    r->tflag = false;
                    pc = (size_t)cmd->target;
                    continue;
                }
                break;
            case 'T':
                if (!r->tflag) {
                    pc = (size_t)cmd->target;
                    continue;
                }
                r->tflag = false;
                break;
            case 'd':
                return SED_END_NOPRINT;
            case 'D': {
                char *nl = memchr(r->ps.data, r->prog->delim, r->ps.len);
                if (!nl) return SED_END_NOPRINT;
                size_t cut = (size_t)(nl - r->ps.data) + 1;
                memmove(r->ps.data, r->ps.data + cut, r->ps.len - cut);
                r->ps.len -= cut;
                r->ps.data[r->ps.len] = '\0';
                *restartWithoutRead = true;
                return SED_END_NOPRINT;
            }
            case 'F': {
                const char *name = r->lineName ? r->lineName : "-";
                sedOutText(r, r->out, name, strlen(name));
                sedOutText(r, r->out, "\n", 1);
                break;
            }
            case 'g':
                sedBufSet(&r->ps, r->hs.data ? r->hs.data : "", r->hs.len);
                break;
            case 'G':
                sedBufAppendChar(&r->ps, r->prog->delim);
                sedBufAppend(&r->ps, r->hs.data ? r->hs.data : "", r->hs.len);
                break;
            case 'h':
                sedBufSet(&r->hs, r->ps.data ? r->ps.data : "", r->ps.len);
                break;
            case 'H':
                sedBufAppendChar(&r->hs, r->prog->delim);
                sedBufAppend(&r->hs, r->ps.data ? r->ps.data : "", r->ps.len);
                break;
            case 'l':
                sedListLine(r, cmd->haveInt ? cmd->intArg : r->lineWrap);
                break;
            case 'L':
                break;
            case 'n':
                if (sedAtEof(r->in)) {
                    if (r->prog->posix) return SED_END_QUIT_SILENT;
                    return SED_END_QUIT;
                }
                if (!r->quiet) sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
                if (!sedReadPattern(r, false)) return SED_END_QUIT_SILENT;
                break;
            case 'N':
                if (sedAtEof(r->in)) {
                    if (r->prog->posix) return SED_END_QUIT_SILENT;
                    return SED_END_QUIT;
                }
                if (!sedReadPattern(r, true)) return SED_END_QUIT;
                break;
            case 'p':
                sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
                break;
            case 'P': {
                char *nl = memchr(r->ps.data, r->prog->delim, r->ps.len);
                if (nl) {
                    sedOutPattern(r, r->out, r->ps.data, (size_t)(nl - r->ps.data), true);
                } else {
                    sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
                }
                break;
            }
            case 'q':
                r->exitCode = cmd->haveInt ? (int)cmd->intArg : 0;
                return SED_END_QUIT;
            case 'Q':
                r->exitCode = cmd->haveInt ? (int)cmd->intArg : 0;
                return SED_END_QUIT_SILENT;
            case 'r':
                sedQueueFile(r, cmd->fileName);
                break;
            case 'R':
                if (cmd->rfileIdx >= 0) sedQueueRLine(r, &prog->rfiles[cmd->rfileIdx]);
                break;
            case 's':
                if (sedSubstitute(r, cmd)) {
                    r->tflag = true;
                    for (int k = 0; k < cmd->printCount + (cmd->eval ? 0 : cmd->printPre); k++)
                        sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
                    if (cmd->outIdx >= 0)
                        sedOutPattern(r, sedResolveOutput(r, cmd->outIdx), r->ps.data, r->ps.len, r->chomped);
                }
                if (r->quit) return SED_END_NOPRINT;
                break;
            case 'v':
                break;
            case 'e':
                if (!*cmd->fileName) {
                    sedEvalPattern(r);
                } else {
                    SedBuf res = {0};
                    if (sedPipeRead(r, cmd->fileName, &res)) {
                        sedOutText(r, r->out, res.data, res.len);
                        fflush(r->out->fp);
                    }
                    sedBufFree(&res);
                }
                if (r->quit) return SED_END_NOPRINT;
                break;
            case 'w':
                sedOutPattern(r, sedResolveOutput(r, cmd->outIdx), r->ps.data, r->ps.len, r->chomped);
                break;
            case 'W': {
                char *nl = memchr(r->ps.data, r->prog->delim, r->ps.len);
                size_t n = nl ? (size_t)(nl - r->ps.data) : r->ps.len;
                sedOutPattern(r, sedResolveOutput(r, cmd->outIdx), r->ps.data, n, nl ? true : r->chomped);
                break;
            }
            case 'x': {
                SedBuf tmp = r->ps;
                r->ps = r->hs;
                r->hs = tmp;
                if (!r->ps.data) sedBufSet(&r->ps, "", 0);
                break;
            }
            case 'y':
                for (size_t k = 0; k < r->ps.len; k++)
                    r->ps.data[k] = (char)cmd->ymap[(unsigned char)r->ps.data[k]];
                break;
            case 'z':
                r->ps.len = 0;
                if (r->ps.data) r->ps.data[0] = '\0';
                break;
            default:
                break;
        }
        pc++;
    }
    return SED_END_PRINT;
}

/* One stream: every line of `in`, output to `out`. */
static void sedRunStream(SedRun *r) {
    bool restart = false;
    for (;;) {
        if (!restart) {
            if (!sedReadPattern(r, false)) break;
        }
        SedEnd end = sedExecute(r, &restart);
        if (r->quit) break;
        if ((end == SED_END_PRINT || end == SED_END_QUIT) && !r->quiet)
            sedOutPattern(r, r->out, r->ps.data, r->ps.len, r->chomped);
        if (end == SED_END_QUIT_SILENT) {
            r->quitRequested = true;
            r->appendQ.len = 0;
            break;
        }
        sedFlushAppend(r);
        if (end == SED_END_QUIT) {
            r->quitRequested = true;
            break;
        }
    }
    sedFlushAppend(r);
}

/* ------------------------------------------------------------------------ */
/* In-place editing                                                          */

static char *sedDirName(const char *path) {
    const char *slash = strrchr(path, '/');
    if (!slash) return strdup(".");
    if (slash == path) return strdup("/");
    return strndup(path, (size_t)(slash - path));
}

static char *sedBackupName(const char *path, const char *suffix) {
    if (!strchr(suffix, '*')) {
        size_t n = strlen(path) + strlen(suffix) + 1;
        char *s = (char *)malloc(n);
        if (s) snprintf(s, n, "%s%s", path, suffix);
        return s;
    }
    /* GNU: each * in the suffix is the file's base name; a suffix with a
     * slash names a path of its own. */
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    SedBuf b = {0};
    if (!strchr(suffix, '/')) {
        char *dir = sedDirName(path);
        if (strchr(path, '/')) {
            sedBufAppend(&b, dir, strlen(dir));
            sedBufAppendChar(&b, '/');
        }
        free(dir);
    }
    for (const char *c = suffix; *c; c++) {
        if (*c == '*') sedBufAppend(&b, base, strlen(base));
        else sedBufAppendChar(&b, *c);
    }
    return b.data;
}

static void sedEditInPlace(SedRun *r, const char *name, const char *suffix, bool followLinks) {
    char resolved[PATH_MAX];
    const char *target = name;
    struct stat lst;
    if (followLinks && lstat(name, &lst) == 0 && S_ISLNK(lst.st_mode)) {
        if (realpath(name, resolved)) target = resolved;
    }
    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "sed: can't read %s: %s\n", name, strerror(errno));
        r->status = 2;
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "sed: couldn't edit %s: not a regular file\n", name);
        r->status = 4;
        return;
    }
    char *dir = sedDirName(target);
    size_t tlen = strlen(dir) + 16;
    char *tmpPath = (char *)malloc(tlen);
    snprintf(tmpPath, tlen, "%s/sedXXXXXX", dir);
    free(dir);
    int fd = mkstemp(tmpPath);
    if (fd < 0) {
        fprintf(stderr, "sed: couldn't open temporary file %s: %s\n", tmpPath, strerror(errno));
        free(tmpPath);
        r->status = 4;
        return;
    }
    /* The edited file keeps the original's mode and, where allowed, owner. */
    (void)fchown(fd, st.st_uid, st.st_gid);
    (void)fchmod(fd, st.st_mode & 07777);
    FILE *tmp = fdopen(fd, "w");
    if (!tmp) {
        close(fd);
        unlink(tmpPath);
        free(tmpPath);
        r->status = 4;
        return;
    }

    char *files[1] = {(char *)target};
    SedInput in = {files, 1, 0, NULL, false, NULL, -1, r->prog->delim, &r->status, false};
    SedOutput out = {tmp, false, false, NULL};
    r->in = &in;
    r->out = &out;
    r->lineNo = 0;
    sedResetRanges(r->prog);
    for (size_t i = 0; i < r->prog->nrfiles; i++) {
        if (r->prog->rfiles[i].fp) rewind(r->prog->rfiles[i].fp);
        r->prog->rfiles[i].eof = false;
    }
    sedRunStream(r);
    sedCloseCurrent(&in);
    bool writeFailed = (fflush(tmp) != 0) || ferror(tmp);
    if (fclose(tmp) != 0) writeFailed = true;
    r->out = r->stdoutOut;
    r->in = NULL;
    if (writeFailed) {
        fprintf(stderr, "sed: couldn't write %s: %s\n", tmpPath, strerror(errno));
        unlink(tmpPath);
        free(tmpPath);
        r->status = 4;
        return;
    }
    if (suffix && *suffix) {
        char *backup = sedBackupName(target, suffix);
        if (backup) {
            unlink(backup);
            if (link(target, backup) != 0 && rename(target, backup) != 0) {
                fprintf(stderr, "sed: cannot rename %s: %s\n", target, strerror(errno));
                free(backup);
                unlink(tmpPath);
                free(tmpPath);
                r->status = 4;
                return;
            }
            free(backup);
        }
    }
    if (rename(tmpPath, target) != 0) {
        fprintf(stderr, "sed: cannot rename %s: %s\n", tmpPath, strerror(errno));
        unlink(tmpPath);
        r->status = 4;
    }
    free(tmpPath);
}

/* ------------------------------------------------------------------------ */
/* Command line                                                              */

static bool sedAddScript(SedBuf *script, const char *text, size_t n) {
    if (!sedBufAppend(script, text, n)) return false;
    return sedBufAppendChar(script, '\n');
}

static bool sedAddScriptFile(SedBuf *script, const char *name) {
    FILE *fp = strcmp(name, "-") == 0 ? stdin : fopen(name, "r");
    if (!fp) {
        fprintf(stderr, "sed: couldn't open file %s: %s\n", name, strerror(errno));
        return false;
    }
    char buf[8192];
    size_t n;
    size_t before = script->len;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) sedBufAppend(script, buf, n);
    if (fp != stdin) fclose(fp);
    if (script->len == before || script->data[script->len - 1] != '\n') sedBufAppendChar(script, '\n');
    return true;
}

static void sedUsage(FILE *fp) {
    fputs("Usage: sed [OPTION]... {SCRIPT} [FILE]...\n"
          "  -n, --quiet, --silent    suppress automatic printing of pattern space\n"
          "  -e SCRIPT, --expression=SCRIPT   add the script to the commands\n"
          "  -f FILE, --file=FILE     add the contents of FILE to the commands\n"
          "  -i[SUFFIX], --in-place[=SUFFIX]  edit files in place (backup if SUFFIX)\n"
          "  --follow-symlinks        follow symlinks when editing in place\n"
          "  -l N, --line-length=N    line-wrap length for the `l' command\n"
          "  -E, -r, --regexp-extended  use extended regular expressions\n"
          "  -s, --separate           treat files as separate, not one stream\n"
          "  -z, --null-data          separate lines by NUL characters\n"
          "  -u, --unbuffered         flush output after every line\n"
          "  --posix                  disable GNU extensions\n",
          fp);
}

int smallclueSedCommand(int argc, char **argv) {
    SedBuf script = {0};
    bool haveScript = false;
    bool quiet = false, extended = false, inPlace = false, separate = false;
    bool nullData = false, unbuffered = false, posix = false, followLinks = false;
    const char *suffix = NULL;
    long lineWrap = 70;
    char **files = (char **)calloc((size_t)argc + 1, sizeof(char *));
    int nfiles = 0;
    int status = 0;
    bool endOfOptions = false;
    char *firstOperand = NULL;

    if (!files) return 4;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (endOfOptions || arg[0] != '-' || arg[1] == '\0') {
            if (!haveScript && !firstOperand) firstOperand = arg;
            else files[nfiles++] = arg;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            endOfOptions = true;
            continue;
        }
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *val = strchr(opt, '=');
            size_t optLen = val ? (size_t)(val - opt) : strlen(opt);
            if (val) val++;
#define SED_LONG(name) (optLen == strlen(name) && strncmp(opt, name, optLen) == 0)
            if (SED_LONG("quiet") || SED_LONG("silent")) quiet = true;
            else if (SED_LONG("regexp-extended")) extended = true;
            else if (SED_LONG("separate")) separate = true;
            else if (SED_LONG("null-data") || SED_LONG("zero-terminated")) nullData = true;
            else if (SED_LONG("unbuffered")) unbuffered = true;
            else if (SED_LONG("posix")) posix = true;
            else if (SED_LONG("follow-symlinks")) followLinks = true;
            else if (SED_LONG("sandbox") || SED_LONG("debug") || SED_LONG("binary")) { /* accepted */ }
            else if (SED_LONG("in-place")) { inPlace = true; suffix = val; }
            else if (SED_LONG("expression") || SED_LONG("file") || SED_LONG("line-length")) {
                if (!val) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "sed: option '--%.*s' requires an argument\n", (int)optLen, opt);
                        status = 1;
                        goto done;
                    }
                    val = argv[++i];
                }
                if (SED_LONG("expression")) {
                    sedAddScript(&script, val, strlen(val));
                    haveScript = true;
                } else if (SED_LONG("file")) {
                    if (!sedAddScriptFile(&script, val)) { status = 1; goto done; }
                    haveScript = true;
                } else {
                    lineWrap = strtol(val, NULL, 10);
                }
            } else if (SED_LONG("help")) {
                sedUsage(stdout);
                goto done;
            } else if (SED_LONG("version")) {
                puts("sed (SmallCLUE) 4.9 -- a GNU sed compatible implementation");
                goto done;
            } else {
                fprintf(stderr, "sed: unknown option -- '%s'\n", opt);
                sedUsage(stderr);
                status = 1;
                goto done;
            }
#undef SED_LONG
            continue;
        }
        for (char *c = arg + 1; *c; c++) {
            switch (*c) {
                case 'n': quiet = true; break;
                case 'E': case 'r': extended = true; break;
                case 's': separate = true; break;
                case 'z': nullData = true; break;
                case 'u': unbuffered = true; break;
                case 'b': break;
                case 'i':
                    inPlace = true;
                    if (c[1]) suffix = c + 1;
                    c += strlen(c) - 1;
                    break;
                case 'e': case 'f': case 'l': {
                    char opt = *c;
                    const char *val = c[1] ? c + 1 : NULL;
                    if (!val) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "sed: option requires an argument -- '%c'\n", opt);
                            sedUsage(stderr);
                            status = 1;
                            goto done;
                        }
                        val = argv[++i];
                    }
                    if (opt == 'e') {
                        sedAddScript(&script, val, strlen(val));
                        haveScript = true;
                    } else if (opt == 'f') {
                        if (!sedAddScriptFile(&script, val)) { status = 1; goto done; }
                        haveScript = true;
                    } else {
                        lineWrap = strtol(val, NULL, 10);
                    }
                    c += strlen(c) - 1;
                    break;
                }
                case 'h':
                    sedUsage(stdout);
                    goto done;
                default:
                    fprintf(stderr, "sed: invalid option -- '%c'\n", *c);
                    sedUsage(stderr);
                    status = 1;
                    goto done;
            }
        }
    }
    if (!haveScript) {
        if (!firstOperand) {
            sedUsage(stderr);
            status = 1;
            goto done;
        }
        sedAddScript(&script, firstOperand, strlen(firstOperand));
    } else if (firstOperand) {
        /* With -e/-f the first operand is a file: put it back in front. */
        memmove(files + 1, files, (size_t)nfiles * sizeof(char *));
        files[0] = firstOperand;
        nfiles++;
    }

    {
        SedProgram prog;
        memset(&prog, 0, sizeof(prog));
        prog.extended = extended;
        prog.posix = posix;
        prog.delim = nullData ? '\0' : '\n';
        if (!sedParseScript(&prog, script.data ? script.data : "", script.len)) {
            status = prog.exitStatus ? prog.exitStatus : 1;
            sedProgramFree(&prog);
            goto done;
        }
        SedOutput stdoutOut = {stdout, false, false, NULL};
        SedRun r;
        memset(&r, 0, sizeof(r));
        r.prog = &prog;
        r.stdoutOut = &stdoutOut;
        r.out = &stdoutOut;
        r.quiet = quiet || prog.quietFromScript;
        r.unbuffered = unbuffered;
        r.lineWrap = lineWrap;
        r.status = 0;
        sedBufSet(&r.ps, "", 0);
        sedBufSet(&r.hs, "", 0);

        char *stdinName[1] = {(char *)"-"};
        if (inPlace) {
            if (nfiles == 0) {
                fprintf(stderr, "sed: no input files\n");
                r.status = 4;
            }
            for (int i = 0; i < nfiles && !r.quitRequested; i++)
                sedEditInPlace(&r, files[i], suffix, followLinks);
        } else if (separate && nfiles > 0) {
            for (int i = 0; i < nfiles && !r.quitRequested; i++) {
                SedInput in = {&files[i], 1, 0, NULL, false, NULL, -1, prog.delim, &r.status, false};
                r.in = &in;
                r.lineNo = 0;
                sedResetRanges(&prog);
                for (size_t k = 0; k < prog.nrfiles; k++) {
                    if (prog.rfiles[k].fp) rewind(prog.rfiles[k].fp);
                    prog.rfiles[k].eof = false;
                }
                sedRunStream(&r);
                sedCloseCurrent(&in);
            }
        } else {
            SedInput in = {nfiles ? files : stdinName, nfiles ? nfiles : 1, 0, NULL, false, NULL, -1,
                           prog.delim, &r.status, false};
            r.in = &in;
            sedResetRanges(&prog);
            sedRunStream(&r);
            sedCloseCurrent(&in);
        }
        if (fflush(stdout) != 0 && r.status == 0) {
            fprintf(stderr, "sed: couldn't flush stdout: %s\n", strerror(errno));
            r.status = 4;
        }
        status = r.status;
        if (r.quitRequested && r.exitCode != 0) status = r.exitCode;
        else if (r.quitRequested && status == 0) status = r.exitCode;
        sedBufFree(&r.ps);
        sedBufFree(&r.hs);
        sedBufFree(&r.appendQ);
        sedProgramFree(&prog);
    }

done:
    sedBufFree(&script);
    free(files);
    return status;
}
