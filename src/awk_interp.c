/*
 * AWK tree-walking interpreter: variables/arrays, field splitting and
 * rebuilding, control-flow signaling, built-in functions, I/O
 * redirection, and the main record-reading driver loop.
 */

#include "awk_interp.h"
#include "awk_value.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---------------- Array (chained hash table) ---------------- */

typedef struct AwkArrayEntry {
    char *key;
    AwkValue val;
    struct AwkArrayEntry *next;
} AwkArrayEntry;

typedef struct AwkArray {
    AwkArrayEntry **buckets;
    int bucketCount;
    int count;
} AwkArray;

static unsigned long awkHashStr(const char *s) {
    unsigned long h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)(*s++);
    return h;
}

static AwkArray *awkArrayNew(void) {
    AwkArray *a = (AwkArray *)calloc(1, sizeof(AwkArray));
    a->bucketCount = 16;
    a->buckets = (AwkArrayEntry **)calloc((size_t)a->bucketCount, sizeof(AwkArrayEntry *));
    return a;
}

static void awkArrayClear(AwkArray *a) {
    for (int i = 0; i < a->bucketCount; ++i) {
        AwkArrayEntry *e = a->buckets[i];
        while (e) {
            AwkArrayEntry *next = e->next;
            free(e->key);
            awkValFree(&e->val);
            free(e);
            e = next;
        }
        a->buckets[i] = NULL;
    }
    a->count = 0;
}

static void awkArrayRehash(AwkArray *a) {
    int newCount = a->bucketCount * 2;
    AwkArrayEntry **newBuckets = (AwkArrayEntry **)calloc((size_t)newCount, sizeof(AwkArrayEntry *));
    for (int i = 0; i < a->bucketCount; ++i) {
        AwkArrayEntry *e = a->buckets[i];
        while (e) {
            AwkArrayEntry *next = e->next;
            unsigned long h = awkHashStr(e->key) % (unsigned long)newCount;
            e->next = newBuckets[h];
            newBuckets[h] = e;
            e = next;
        }
    }
    free(a->buckets);
    a->buckets = newBuckets;
    a->bucketCount = newCount;
}

static AwkArrayEntry *awkArrayFind(AwkArray *a, const char *key) {
    unsigned long h = awkHashStr(key) % (unsigned long)a->bucketCount;
    for (AwkArrayEntry *e = a->buckets[h]; e; e = e->next) {
        if (strcmp(e->key, key) == 0) return e;
    }
    return NULL;
}

/* Creates the slot (with an uninitialized value) if it doesn't exist --
 * this matches real awk's "referencing arr[x] creates it" behavior. */
static AwkArrayEntry *awkArrayGetOrCreate(AwkArray *a, const char *key) {
    AwkArrayEntry *e = awkArrayFind(a, key);
    if (e) return e;
    if (a->count + 1 > a->bucketCount * 2) awkArrayRehash(a);
    unsigned long h = awkHashStr(key) % (unsigned long)a->bucketCount;
    e = (AwkArrayEntry *)malloc(sizeof(AwkArrayEntry));
    e->key = strdup(key);
    e->val = awkValUninit();
    e->next = a->buckets[h];
    a->buckets[h] = e;
    a->count++;
    return e;
}

static bool awkArrayDelete(AwkArray *a, const char *key) {
    unsigned long h = awkHashStr(key) % (unsigned long)a->bucketCount;
    AwkArrayEntry **pp = &a->buckets[h];
    while (*pp) {
        if (strcmp((*pp)->key, key) == 0) {
            AwkArrayEntry *victim = *pp;
            *pp = victim->next;
            free(victim->key);
            awkValFree(&victim->val);
            free(victim);
            a->count--;
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

/* ---------------- Variables / scope ---------------- */

typedef struct {
    char *name;
    bool isArray;
    AwkValue scalar;
    AwkArray *arr;
} AwkVar;

typedef struct {
    char **paramNames;
    int paramCount;
    AwkValue *scalars;
    AwkArray **arrays;   /* non-NULL once known to be an array (aliased or fresh local) */
    bool *isArray;
    bool *ownsArray;     /* true if `arrays[i]` was freshly allocated here (not aliased) */
} AwkFrame;

typedef struct AwkStream {
    char *name;
    FILE *fp;
    bool isPipe;
    bool forWrite;
    struct AwkStream *next;
} AwkStream;

typedef enum { AWK_SIG_NORMAL, AWK_SIG_BREAK, AWK_SIG_CONTINUE, AWK_SIG_NEXT,
               AWK_SIG_NEXTFILE, AWK_SIG_EXIT, AWK_SIG_RETURN } AwkSignal;

typedef struct {
    char *name;
    char **params;
    int paramCount;
    AwkNode *body;
    bool *paramIsArray; /* static-analysis result: does the body use this
                         * param as an array? Lets awkCallUser correctly
                         * auto-vivify-and-alias a never-yet-used bare
                         * variable passed in that position, instead of
                         * defaulting to scalar-by-value (which would
                         * silently break the extremely common "pass an
                         * empty array for the function to fill" idiom). */
} AwkFunc;

typedef struct {
    AwkProgram *prog;
    AwkVar *globals;
    int globalCount, globalCap;
    AwkFunc *funcs;
    int funcCount;
    AwkFrame *frames;
    int frameDepth, frameCap;
    AwkStream *streams;
    AwkValue returnValue;
    int exitCode;
    bool exiting;

    char *record;
    char **fields;
    int nfields, fieldsCap;

    FILE *curFile;
    bool curFileIsOwned;
    char **argv;
    int argc;
    int argIndex;
    bool anyFileOpened;

    unsigned int randState;
    bool rangeActive; /* for the currently-evaluating range pattern (single flag; enough since
                          rules execute serially and only one range test is "live" at a time
                          per rule -- indexed per-rule via a small side array below) */
    bool *rangeActiveByRule;
} AwkInterp;

static AwkInterp gInterp;

/* ---------------- Global variable access ---------------- */

static AwkVar *awkFindGlobal(const char *name) {
    for (int i = 0; i < gInterp.globalCount; ++i) {
        if (strcmp(gInterp.globals[i].name, name) == 0) return &gInterp.globals[i];
    }
    return NULL;
}

static AwkVar *awkGetOrCreateGlobal(const char *name) {
    AwkVar *v = awkFindGlobal(name);
    if (v) return v;
    if (gInterp.globalCount == gInterp.globalCap) {
        gInterp.globalCap = gInterp.globalCap ? gInterp.globalCap * 2 : 32;
        gInterp.globals = (AwkVar *)realloc(gInterp.globals, sizeof(AwkVar) * (size_t)gInterp.globalCap);
    }
    AwkVar *nv = &gInterp.globals[gInterp.globalCount++];
    nv->name = strdup(name);
    nv->isArray = false;
    nv->scalar = awkValUninit();
    nv->arr = NULL;
    return nv;
}

static AwkFrame *awkCurFrame(void) {
    if (gInterp.frameDepth == 0) return NULL;
    return &gInterp.frames[gInterp.frameDepth - 1];
}

static int awkFrameParamIndex(AwkFrame *fr, const char *name) {
    if (!fr) return -1;
    for (int i = 0; i < fr->paramCount; ++i) {
        if (strcmp(fr->paramNames[i], name) == 0) return i;
    }
    return -1;
}

static AwkArray *awkGetArrayFor(const char *name) {
    AwkFrame *fr = awkCurFrame();
    int pi = awkFrameParamIndex(fr, name);
    if (pi >= 0) {
        if (!fr->arrays[pi]) {
            fr->arrays[pi] = awkArrayNew();
            fr->isArray[pi] = true;
            fr->ownsArray[pi] = true;
        }
        return fr->arrays[pi];
    }
    AwkVar *v = awkGetOrCreateGlobal(name);
    if (!v->arr) {
        v->arr = awkArrayNew();
        v->isArray = true;
    }
    return v->arr;
}

static AwkValue awkGetScalar(const char *name) {
    AwkFrame *fr = awkCurFrame();
    int pi = awkFrameParamIndex(fr, name);
    if (pi >= 0) return awkValCopy(&fr->scalars[pi]);
    AwkVar *v = awkGetOrCreateGlobal(name);
    return awkValCopy(&v->scalar);
}

static void awkSetScalar(const char *name, AwkValue val) {
    AwkFrame *fr = awkCurFrame();
    int pi = awkFrameParamIndex(fr, name);
    if (pi >= 0) {
        awkValFree(&fr->scalars[pi]);
        fr->scalars[pi] = val;
        return;
    }
    AwkVar *v = awkGetOrCreateGlobal(name);
    awkValFree(&v->scalar);
    v->scalar = val;
}

static const char *awkGetVarStr(const char *name) {
    /* returns a pointer valid until the variable is next reassigned --
     * used only for built-in control vars we immediately format/copy */
    AwkVar *v = awkFindGlobal(name);
    if (!v) return "";
    if (v->scalar.kind == AWK_V_STR || v->scalar.kind == AWK_V_STRNUM) return v->scalar.str ? v->scalar.str : "";
    static char buf[64];
    char *s = awkToStrFmt(&v->scalar, "%.6g");
    snprintf(buf, sizeof(buf), "%s", s);
    free(s);
    return buf;
}

static double awkGetVarNum(const char *name) {
    AwkVar *v = awkFindGlobal(name);
    if (!v) return 0.0;
    return awkToNum(&v->scalar);
}

/* ---------------- Regex helpers ---------------- */

static bool awkRegexCompile(regex_t *re, const char *pattern) {
    return regcomp(re, pattern, REG_EXTENDED) == 0;
}

/* ---------------- Field management ---------------- */

static void awkFreeFields(void) {
    for (int i = 0; i < gInterp.nfields; ++i) free(gInterp.fields[i]);
    gInterp.nfields = 0;
}

static void awkSplitLineWithFS(const char *line, const char *fs, char ***outFields, int *outCount) {
    int cap = 8, cnt = 0;
    char **fields = (char **)malloc(sizeof(char *) * (size_t)cap);

    if (strcmp(fs, " ") == 0) {
        const char *p = line;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            if (!*p) break;
            const char *start = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
            size_t len = (size_t)(p - start);
            if (cnt == cap) { cap *= 2; fields = (char **)realloc(fields, sizeof(char *) * (size_t)cap); }
            fields[cnt] = (char *)malloc(len + 1);
            memcpy(fields[cnt], start, len);
            fields[cnt][len] = '\0';
            cnt++;
        }
    } else if (strlen(fs) == 1) {
        char sep = fs[0];
        const char *start = line;
        const char *p = line;
        for (;;) {
            if (*p == sep || *p == '\0') {
                size_t len = (size_t)(p - start);
                if (cnt == cap) { cap *= 2; fields = (char **)realloc(fields, sizeof(char *) * (size_t)cap); }
                fields[cnt] = (char *)malloc(len + 1);
                memcpy(fields[cnt], start, len);
                fields[cnt][len] = '\0';
                cnt++;
                if (*p == '\0') break;
                p++;
                start = p;
            } else {
                p++;
            }
        }
    } else if (fs[0] == '\0') {
        /* empty FS: split into individual characters */
        for (const char *p = line; *p; ++p) {
            if (cnt == cap) { cap *= 2; fields = (char **)realloc(fields, sizeof(char *) * (size_t)cap); }
            fields[cnt] = (char *)malloc(2);
            fields[cnt][0] = *p;
            fields[cnt][1] = '\0';
            cnt++;
        }
    } else {
        regex_t re;
        if (!awkRegexCompile(&re, fs)) {
            /* fall back to literal single-char-of-first-byte behavior on bad regex */
            fields[cnt++] = strdup(line);
        } else {
            const char *p = line;
            regmatch_t m;
            while (*p) {
                if (regexec(&re, p, 1, &m, 0) == 0 && m.rm_so != m.rm_eo) {
                    size_t len = (size_t)m.rm_so;
                    if (cnt == cap) { cap *= 2; fields = (char **)realloc(fields, sizeof(char *) * (size_t)cap); }
                    fields[cnt] = (char *)malloc(len + 1);
                    memcpy(fields[cnt], p, len);
                    fields[cnt][len] = '\0';
                    cnt++;
                    p += m.rm_eo;
                } else {
                    if (cnt == cap) { cap *= 2; fields = (char **)realloc(fields, sizeof(char *) * (size_t)cap); }
                    fields[cnt] = strdup(p);
                    cnt++;
                    break;
                }
            }
            if (*line == '\0') { /* empty record -> zero fields */ }
            regfree(&re);
        }
    }
    *outFields = fields;
    *outCount = cnt;
}

static bool gAwkParagraphMode = false;

static void awkResplitFields(void) {
    awkFreeFields();
    const char *fs = awkGetVarStr("FS");
    char **fields = NULL;
    int cnt = 0;
    if (gAwkParagraphMode && strcmp(fs, " ") != 0) {
        /* newline is always an additional separator in paragraph mode */
        char *rec = strdup(gInterp.record);
        char *saveptr = NULL;
        char *line = strtok_r(rec, "\n", &saveptr);
        while (line) {
            char **sub = NULL; int subCnt = 0;
            awkSplitLineWithFS(line, fs, &sub, &subCnt);
            for (int i = 0; i < subCnt; ++i) {
                fields = (char **)realloc(fields, sizeof(char *) * (size_t)(cnt + 1));
                fields[cnt++] = sub[i];
            }
            free(sub);
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(rec);
    } else {
        awkSplitLineWithFS(gInterp.record, fs, &fields, &cnt);
    }
    gInterp.fields = fields;
    gInterp.nfields = cnt;
    gInterp.fieldsCap = cnt;
    awkSetScalar("NF", awkValNum(cnt));
}

static void awkRebuildRecord(void) {
    const char *ofs = awkGetVarStr("OFS");
    size_t total = 0;
    size_t ofsLen = strlen(ofs);
    for (int i = 0; i < gInterp.nfields; ++i) total += strlen(gInterp.fields[i]);
    if (gInterp.nfields > 1) total += ofsLen * (size_t)(gInterp.nfields - 1);
    char *rec = (char *)malloc(total + 1);
    rec[0] = '\0';
    for (int i = 0; i < gInterp.nfields; ++i) {
        if (i > 0) strcat(rec, ofs);
        strcat(rec, gInterp.fields[i]);
    }
    free(gInterp.record);
    gInterp.record = rec;
}

static void awkSetRecord(const char *s) {
    free(gInterp.record);
    gInterp.record = strdup(s);
    awkResplitFields();
}

static const char *awkGetField(int idx) {
    if (idx == 0) return gInterp.record ? gInterp.record : "";
    if (idx < 0) return "";
    if (idx > gInterp.nfields) return "";
    return gInterp.fields[idx - 1];
}

static void awkSetField(int idx, const char *val) {
    if (idx == 0) {
        awkSetRecord(val);
        return;
    }
    if (idx < 0) return;
    if (idx > gInterp.nfields) {
        int oldCount = gInterp.nfields;
        gInterp.fields = (char **)realloc(gInterp.fields, sizeof(char *) * (size_t)idx);
        for (int i = oldCount; i < idx; ++i) gInterp.fields[i] = strdup("");
        gInterp.nfields = idx;
        awkSetScalar("NF", awkValNum(idx));
    }
    free(gInterp.fields[idx - 1]);
    gInterp.fields[idx - 1] = strdup(val);
    awkRebuildRecord();
}

static void awkSetNF(int newNF) {
    if (newNF < 0) newNF = 0;
    if (newNF < gInterp.nfields) {
        for (int i = newNF; i < gInterp.nfields; ++i) free(gInterp.fields[i]);
        gInterp.nfields = newNF;
    } else if (newNF > gInterp.nfields) {
        gInterp.fields = (char **)realloc(gInterp.fields, sizeof(char *) * (size_t)newNF);
        for (int i = gInterp.nfields; i < newNF; ++i) gInterp.fields[i] = strdup("");
        gInterp.nfields = newNF;
    }
    awkSetScalar("NF", awkValNum(newNF));
    awkRebuildRecord();
}

/* ---------------- Streams (I/O redirection) ---------------- */

static AwkStream *awkFindStream(const char *name) {
    for (AwkStream *s = gInterp.streams; s; s = s->next) {
        if (strcmp(s->name, name) == 0) return s;
    }
    return NULL;
}

static FILE *awkOpenOutputStream(const char *name, AwkRedirKind kind) {
    AwkStream *s = awkFindStream(name);
    if (s && s->forWrite) return s->fp;
    const char *mode;
    FILE *fp;
    bool isPipe = (kind == AWK_REDIR_PIPE);
    if (isPipe) {
        fp = popen(name, "w");
    } else {
        mode = (kind == AWK_REDIR_APPEND) ? "a" : "w";
        fp = fopen(name, mode);
    }
    if (!fp) return NULL;
    AwkStream *ns = (AwkStream *)calloc(1, sizeof(AwkStream));
    ns->name = strdup(name);
    ns->fp = fp;
    ns->isPipe = isPipe;
    ns->forWrite = true;
    ns->next = gInterp.streams;
    gInterp.streams = ns;
    return fp;
}

static FILE *awkOpenInputStream(const char *name, bool isPipe) {
    AwkStream *s = awkFindStream(name);
    if (s && !s->forWrite) return s->fp;
    FILE *fp = isPipe ? popen(name, "r") : fopen(name, "r");
    if (!fp) return NULL;
    AwkStream *ns = (AwkStream *)calloc(1, sizeof(AwkStream));
    ns->name = strdup(name);
    ns->fp = fp;
    ns->isPipe = isPipe;
    ns->forWrite = false;
    ns->next = gInterp.streams;
    gInterp.streams = ns;
    return fp;
}

static int awkCloseStream(const char *name) {
    AwkStream **pp = &gInterp.streams;
    while (*pp) {
        if (strcmp((*pp)->name, name) == 0) {
            AwkStream *victim = *pp;
            int rc = victim->isPipe ? pclose(victim->fp) : fclose(victim->fp);
            *pp = victim->next;
            free(victim->name);
            free(victim);
            return rc;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

static void awkCloseAllStreams(void) {
    AwkStream *s = gInterp.streams;
    while (s) {
        AwkStream *next = s->next;
        if (s->isPipe) pclose(s->fp); else fclose(s->fp);
        free(s->name);
        free(s);
        s = next;
    }
    gInterp.streams = NULL;
}

/* ---------------- Forward declarations ---------------- */

static AwkValue awkEval(AwkNode *n);
static AwkSignal awkExec(AwkNode *n);
static void awkAssignLvalue(AwkNode *lv, AwkValue val);
static AwkValue awkEvalLvalueCurrent(AwkNode *lv);
static bool awkGetlineFillLine(FILE *fp, char **outLine);
static bool awkNextMainRecord(char **outLine);

/* ---------------- Function table ---------------- */

static AwkFunc *awkFindFunc(const char *name) {
    for (int i = 0; i < gInterp.funcCount; ++i) {
        if (strcmp(gInterp.funcs[i].name, name) == 0) return &gInterp.funcs[i];
    }
    return NULL;
}

/* ---------------- sprintf/printf ---------------- */

static char *awkSprintfImpl(const char *fmt, AwkNode **args, int argCount, int startArg) {
    size_t cap = 256, len = 0;
    char *out = (char *)malloc(cap);
    out[0] = '\0';
    int argi = startArg;

    #define ENSURE(n) do { if (len + (n) + 1 > cap) { while (len + (n) + 1 > cap) cap *= 2; out = (char*)realloc(out, cap); } } while (0)
    #define APPEND_STR(s) do { size_t sl = strlen(s); ENSURE(sl); memcpy(out+len, s, sl); len += sl; out[len]='\0'; } while(0)

    for (const char *p = fmt; *p; ) {
        if (*p != '%') { char buf[2] = {*p,0}; APPEND_STR(buf); p++; continue; }
        const char *specStart = p;
        p++;
        if (*p == '%') { APPEND_STR("%"); p++; continue; }
        char spec[64];
        size_t si = 0;
        spec[si++] = '%';
        while (*p == '-' || *p == '+' || *p == ' ' || *p == '0' || *p == '#') { spec[si++] = *p++; }
        while (isdigit((unsigned char)*p)) { spec[si++] = *p++; }
        if (*p == '.') {
            spec[si++] = *p++;
            while (isdigit((unsigned char)*p)) { spec[si++] = *p++; }
        }
        if (!*p) { spec[si] = '\0'; APPEND_STR(specStart); break; }
        char conv = *p++;
        char buf[512];
        AwkValue av = awkValUninit();
        bool haveArg = false;
        if (conv != '%' && argi < argCount) {
            av = awkEval(args[argi]);
            argi++;
            haveArg = true;
        }
        switch (conv) {
            case 'd': case 'i': {
                spec[si++] = 'l'; spec[si++] = 'l'; spec[si++] = 'd'; spec[si] = '\0';
                long long v = haveArg ? (long long)awkToNum(&av) : 0;
                snprintf(buf, sizeof(buf), spec, v);
                APPEND_STR(buf);
                break;
            }
            case 'o': case 'x': case 'X': case 'u': {
                spec[si++] = 'l'; spec[si++] = 'l'; spec[si++] = conv; spec[si] = '\0';
                long long v = haveArg ? (long long)awkToNum(&av) : 0;
                unsigned long long uv = (unsigned long long)v;
                snprintf(buf, sizeof(buf), spec, uv);
                APPEND_STR(buf);
                break;
            }
            case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': {
                spec[si++] = conv; spec[si] = '\0';
                double v = haveArg ? awkToNum(&av) : 0.0;
                snprintf(buf, sizeof(buf), spec, v);
                APPEND_STR(buf);
                break;
            }
            case 'c': {
                spec[si++] = 's'; spec[si] = '\0';
                char cbuf[2] = {0, 0};
                const char *sarg = cbuf;
                char *heapStr = NULL;
                if (haveArg) {
                    if (av.kind == AWK_V_STR || (av.kind == AWK_V_STRNUM && !awkIsNumericCtx(&av))) {
                        cbuf[0] = (av.str && av.str[0]) ? av.str[0] : '\0';
                    } else if (av.kind == AWK_V_STRNUM) {
                        cbuf[0] = (av.str && av.str[0]) ? av.str[0] : '\0';
                    } else {
                        cbuf[0] = (char)(int)awkToNum(&av);
                    }
                }
                (void)heapStr;
                snprintf(buf, sizeof(buf), spec, sarg);
                APPEND_STR(buf);
                break;
            }
            case 's': {
                spec[si++] = 's'; spec[si] = '\0';
                char *sv = haveArg ? awkToStrFmt(&av, "%.6g") : strdup("");
                int need = snprintf(NULL, 0, spec, sv);
                if (need < 0) need = 0;
                char *tmp = (char *)malloc((size_t)need + 1);
                snprintf(tmp, (size_t)need + 1, spec, sv);
                APPEND_STR(tmp);
                free(tmp);
                free(sv);
                break;
            }
            default: {
                spec[si++] = conv; spec[si] = '\0';
                APPEND_STR(spec);
                break;
            }
        }
        if (haveArg) awkValFree(&av);
    }
    #undef APPEND_STR
    #undef ENSURE
    return out;
}

/* ---------------- Built-in functions ---------------- */

/* substr per the exact algorithm verified against real BusyBox awk:
 * lo = max(0, m-1); hi = (n given) ? clamp(lo+n, lo, strlen) : strlen. */
static char *awkBuiltinSubstr(const char *s, double mArg, bool haveN, double nArg) {
    int slen = (int)strlen(s);
    long m = (long)mArg;
    long lo0 = m - 1;
    long lo = lo0 < 0 ? 0 : lo0;
    long hi;
    if (!haveN) {
        hi = slen;
    } else {
        long n = (long)nArg;
        hi = lo + n;
        if (hi > slen) hi = slen;
        if (hi < lo) hi = lo;
    }
    if (lo > slen) lo = slen;
    if (lo >= hi) return strdup("");
    size_t len = (size_t)(hi - lo);
    char *r = (char *)malloc(len + 1);
    memcpy(r, s + lo, len);
    r[len] = '\0';
    return r;
}

static int gAwkRstart = 0, gAwkRlength = -1;

static int awkDoSub(const char *pattern, const char *repl, const char *target, bool global, char **outResult) {
    regex_t re;
    if (!awkRegexCompile(&re, pattern)) {
        *outResult = strdup(target);
        return 0;
    }
    size_t cap = strlen(target) * 2 + 64, len = 0;
    char *out = (char *)malloc(cap);
    out[0] = '\0';
    #define ENSURE2(n) do { if (len + (n) + 1 > cap) { while (len + (n) + 1 > cap) cap *= 2; out = (char*)realloc(out, cap); } } while (0)
    #define APPEND_N(s, n) do { ENSURE2(n); memcpy(out+len, s, n); len += (n); out[len]='\0'; } while(0)

    const char *p = target;
    int count = 0;
    bool prevEmptyAtStart = false;
    while (*p) {
        regmatch_t m;
        int rc = regexec(&re, p, 1, &m, (p == target) ? 0 : REG_NOTBOL);
        if (rc != 0) {
            APPEND_N(p, strlen(p));
            break;
        }
        APPEND_N(p, (size_t)m.rm_so);
        if (m.rm_so == m.rm_eo) {
            /* empty match: emit the char at this position (if any) and advance,
             * to avoid an infinite loop, matching common awk gsub behavior */
            if (!global) {
                for (const char *rp = repl; *rp; ++rp) {
                    if (*rp == '&') { /* empty match, nothing to substitute */ }
                    else if (*rp == '\\' && (rp[1] == '&' || rp[1] == '\\')) { char c = rp[1]; APPEND_N(&c, 1); rp++; }
                    else APPEND_N(rp, 1);
                }
                count++;
                APPEND_N(p + m.rm_so, strlen(p + m.rm_so));
                p += strlen(p);
                break;
            }
            for (const char *rp = repl; *rp; ++rp) {
                if (*rp == '&') { }
                else if (*rp == '\\' && (rp[1] == '&' || rp[1] == '\\')) { char c = rp[1]; APPEND_N(&c, 1); rp++; }
                else APPEND_N(rp, 1);
            }
            count++;
            if (p[m.rm_so]) {
                APPEND_N(p + m.rm_so, 1);
                p += m.rm_so + 1;
            } else {
                p += m.rm_so;
                break;
            }
            prevEmptyAtStart = true;
            continue;
        }
        prevEmptyAtStart = false;
        (void)prevEmptyAtStart;
        const char *matched = p + m.rm_so;
        size_t matchedLen = (size_t)(m.rm_eo - m.rm_so);
        for (const char *rp = repl; *rp; ++rp) {
            if (*rp == '&') { APPEND_N(matched, matchedLen); }
            else if (*rp == '\\' && (rp[1] == '&' || rp[1] == '\\')) { char c = rp[1]; APPEND_N(&c, 1); rp++; }
            else APPEND_N(rp, 1);
        }
        count++;
        p += m.rm_eo;
        if (!global) {
            APPEND_N(p, strlen(p));
            break;
        }
    }
    #undef APPEND_N
    #undef ENSURE2
    regfree(&re);
    *outResult = out;
    return count;
}

static AwkValue awkCallBuiltin(AwkNode *call) {
    const char *name = call->str;
    AwkNode **args = call->list;
    int argc = call->listCount;

    if (strcmp(name, "length") == 0) {
        if (argc == 0) return awkValNum((double)strlen(awkGetField(0)));
        if (args[0]->kind == AWK_E_VAR) {
            AwkFrame *fr = awkCurFrame();
            int pi = awkFrameParamIndex(fr, args[0]->str);
            bool isArr = (pi >= 0) ? (fr->isArray && fr->isArray[pi]) : false;
            AwkVar *gv = (pi < 0) ? awkFindGlobal(args[0]->str) : NULL;
            if (isArr || (gv && gv->isArray)) {
                AwkArray *a = awkGetArrayFor(args[0]->str);
                return awkValNum((double)a->count);
            }
        }
        AwkValue v = awkEval(args[0]);
        char *s = awkToStrFmt(&v, "%.6g");
        double r = (double)strlen(s);
        free(s);
        awkValFree(&v);
        return awkValNum(r);
    }
    if (strcmp(name, "substr") == 0) {
        AwkValue sv = awkEval(args[0]);
        char *s = awkToStrFmt(&sv, "%.6g");
        awkValFree(&sv);
        double m = 1, nArg = 0; bool haveN = argc >= 3;
        if (argc >= 2) { AwkValue mv = awkEval(args[1]); m = awkToNum(&mv); awkValFree(&mv); }
        if (haveN) { AwkValue nv = awkEval(args[2]); nArg = awkToNum(&nv); awkValFree(&nv); }
        char *r = awkBuiltinSubstr(s, m, haveN, nArg);
        free(s);
        AwkValue rv = awkValStr(r);
        free(r);
        return rv;
    }
    if (strcmp(name, "index") == 0) {
        AwkValue a = awkEval(args[0]); AwkValue b = awkEval(args[1]);
        char *sa = awkToStrFmt(&a, "%.6g"); char *sb = awkToStrFmt(&b, "%.6g");
        char *found = strstr(sa, sb);
        double r = found ? (double)(found - sa + 1) : 0.0;
        free(sa); free(sb);
        awkValFree(&a); awkValFree(&b);
        return awkValNum(r);
    }
    if (strcmp(name, "split") == 0) {
        AwkValue sv = awkEval(args[0]);
        char *s = awkToStrFmt(&sv, "%.6g");
        awkValFree(&sv);
        AwkArray *arr = awkGetArrayFor(args[1]->str);
        awkArrayClear(arr);
        char *fs;
        if (argc >= 3) {
            if (args[2]->kind == AWK_E_REGEX) {
                fs = strdup(args[2]->str);
            } else {
                AwkValue fv = awkEval(args[2]);
                fs = awkToStrFmt(&fv, "%.6g");
                awkValFree(&fv);
            }
        } else {
            fs = strdup(awkGetVarStr("FS"));
        }
        char **fields = NULL; int cnt = 0;
        if (s[0] != '\0') awkSplitLineWithFS(s, fs, &fields, &cnt);
        for (int i = 0; i < cnt; ++i) {
            char key[32];
            snprintf(key, sizeof(key), "%d", i + 1);
            AwkArrayEntry *e = awkArrayGetOrCreate(arr, key);
            awkValFree(&e->val);
            e->val = awkValStrNum(fields[i]);
            free(fields[i]);
        }
        free(fields);
        free(fs);
        free(s);
        return awkValNum((double)cnt);
    }
    if (strcmp(name, "sub") == 0 || strcmp(name, "gsub") == 0) {
        bool global = (name[0] == 'g');
        char *pattern;
        if (args[0]->kind == AWK_E_REGEX) pattern = strdup(args[0]->str);
        else { AwkValue pv = awkEval(args[0]); pattern = awkToStrFmt(&pv, "%.6g"); awkValFree(&pv); }
        AwkValue rv = awkEval(args[1]);
        char *repl = awkToStrFmt(&rv, "%.6g");
        awkValFree(&rv);
        AwkNode *targetNode = (argc >= 3) ? args[2] : NULL;
        char *targetStr;
        if (targetNode) {
            AwkValue tv = awkEvalLvalueCurrent(targetNode);
            targetStr = awkToStrFmt(&tv, "%.6g");
            awkValFree(&tv);
        } else {
            targetStr = strdup(awkGetField(0));
        }
        char *result;
        int count = awkDoSub(pattern, repl, targetStr, global, &result);
        if (count > 0) {
            if (targetNode) awkAssignLvalue(targetNode, awkValStr(result));
            else awkSetField(0, result);
        }
        free(pattern); free(repl); free(targetStr); free(result);
        return awkValNum((double)count);
    }
    if (strcmp(name, "match") == 0) {
        AwkValue sv = awkEval(args[0]);
        char *s = awkToStrFmt(&sv, "%.6g");
        awkValFree(&sv);
        char *pattern;
        if (args[1]->kind == AWK_E_REGEX) pattern = strdup(args[1]->str);
        else { AwkValue pv = awkEval(args[1]); pattern = awkToStrFmt(&pv, "%.6g"); awkValFree(&pv); }
        regex_t re;
        double result = 0;
        if (awkRegexCompile(&re, pattern)) {
            regmatch_t m;
            if (regexec(&re, s, 1, &m, 0) == 0) {
                gAwkRstart = (int)m.rm_so + 1;
                gAwkRlength = (int)(m.rm_eo - m.rm_so);
                result = gAwkRstart;
            } else {
                gAwkRstart = 0;
                gAwkRlength = -1;
            }
            regfree(&re);
        }
        awkSetScalar("RSTART", awkValNum(gAwkRstart));
        awkSetScalar("RLENGTH", awkValNum(gAwkRlength));
        free(s); free(pattern);
        return awkValNum(result);
    }
    if (strcmp(name, "sprintf") == 0) {
        AwkValue fv = awkEval(args[0]);
        char *fmt = awkToStrFmt(&fv, "%.6g");
        awkValFree(&fv);
        char *r = awkSprintfImpl(fmt, args, argc, 1);
        free(fmt);
        AwkValue rv = awkValStr(r);
        free(r);
        return rv;
    }
    if (strcmp(name, "sin") == 0 || strcmp(name, "cos") == 0 || strcmp(name, "exp") == 0 ||
        strcmp(name, "log") == 0 || strcmp(name, "sqrt") == 0 || strcmp(name, "int") == 0) {
        AwkValue v = awkEval(args[0]);
        double x = awkToNum(&v);
        awkValFree(&v);
        double r;
        if (strcmp(name, "sin") == 0) r = sin(x);
        else if (strcmp(name, "cos") == 0) r = cos(x);
        else if (strcmp(name, "exp") == 0) r = exp(x);
        else if (strcmp(name, "log") == 0) r = log(x);
        else if (strcmp(name, "sqrt") == 0) r = sqrt(x);
        else r = trunc(x);
        return awkValNum(r);
    }
    if (strcmp(name, "atan2") == 0) {
        AwkValue a = awkEval(args[0]); AwkValue b = awkEval(args[1]);
        double r = atan2(awkToNum(&a), awkToNum(&b));
        awkValFree(&a); awkValFree(&b);
        return awkValNum(r);
    }
    if (strcmp(name, "rand") == 0) {
        double r = (double)(rand_r(&gInterp.randState) % 1000000) / 1000000.0;
        return awkValNum(r);
    }
    if (strcmp(name, "srand") == 0) {
        static unsigned int prevSeed = 0;
        unsigned int newSeed;
        if (argc >= 1) {
            AwkValue v = awkEval(args[0]);
            newSeed = (unsigned int)awkToNum(&v);
            awkValFree(&v);
        } else {
            newSeed = (unsigned int)time(NULL);
        }
        double old = prevSeed;
        prevSeed = newSeed;
        gInterp.randState = newSeed;
        return awkValNum(old);
    }
    if (strcmp(name, "tolower") == 0 || strcmp(name, "toupper") == 0) {
        AwkValue v = awkEval(args[0]);
        char *s = awkToStrFmt(&v, "%.6g");
        awkValFree(&v);
        bool upper = (name[2] == 'u');
        for (char *p = s; *p; ++p) *p = upper ? (char)toupper((unsigned char)*p) : (char)tolower((unsigned char)*p);
        AwkValue rv = awkValStr(s);
        free(s);
        return rv;
    }
    if (strcmp(name, "system") == 0) {
        AwkValue v = awkEval(args[0]);
        char *cmd = awkToStrFmt(&v, "%.6g");
        awkValFree(&v);
        fflush(stdout);
        int rc = system(cmd);
        free(cmd);
        int code = WIFEXITED(rc) ? WEXITSTATUS(rc) : (WIFSIGNALED(rc) ? 128 + WTERMSIG(rc) : -1);
        return awkValNum(code);
    }
    if (strcmp(name, "close") == 0) {
        AwkValue v = awkEval(args[0]);
        char *n = awkToStrFmt(&v, "%.6g");
        awkValFree(&v);
        int rc = awkCloseStream(n);
        free(n);
        return awkValNum(rc);
    }
    if (strcmp(name, "fflush") == 0) {
        if (argc == 0) { fflush(NULL); return awkValNum(0); }
        AwkValue v = awkEval(args[0]);
        char *n = awkToStrFmt(&v, "%.6g");
        awkValFree(&v);
        AwkStream *s = awkFindStream(n);
        int rc = s ? fflush(s->fp) : fflush(NULL);
        free(n);
        return awkValNum(rc);
    }
    fprintf(stderr, "awk: unknown function '%s'\n", name);
    return awkValUninit();
}

/* ---------------- User function calls ---------------- */

static AwkValue awkCallUser(AwkNode *call) {
    AwkFunc *fn = awkFindFunc(call->str);
    if (!fn) {
        fprintf(stderr, "awk: calling undefined function %s\n", call->str);
        return awkValUninit();
    }
    AwkFrame fr;
    memset(&fr, 0, sizeof(fr));
    fr.paramCount = fn->paramCount;
    fr.paramNames = fn->params;
    fr.scalars = (AwkValue *)calloc((size_t)fn->paramCount, sizeof(AwkValue));
    fr.arrays = (AwkArray **)calloc((size_t)fn->paramCount, sizeof(AwkArray *));
    fr.isArray = (bool *)calloc((size_t)fn->paramCount, sizeof(bool));
    fr.ownsArray = (bool *)calloc((size_t)fn->paramCount, sizeof(bool));
    for (int i = 0; i < fn->paramCount; ++i) fr.scalars[i] = awkValUninit();

    int nargs = call->listCount;
    for (int i = 0; i < fn->paramCount; ++i) {
        if (i >= nargs) continue;
        AwkNode *argNode = call->list[i];
        if (argNode->kind == AWK_E_VAR) {
            /* Could be an array (aliased by reference) or a scalar (by
             * value). If it's already committed one way or the other,
             * respect that. If it's genuinely untyped (never
             * referenced), consult the callee's static usage analysis
             * (awkAnalyzeFunctionArrayParams) -- this is what makes the
             * extremely common "pass an empty array for the function to
             * fill" idiom work: without it, a never-yet-used bare name
             * would default to scalar-by-value, and the callee's writes
             * would land in a throwaway local array the caller never
             * sees (a real bug caught by testing this exact pattern). */
            AwkFrame *callerFrame = awkCurFrame();
            int pi = awkFrameParamIndex(callerFrame, argNode->str);
            bool isArr = false;
            AwkArray *existingArr = NULL;
            bool isUntyped = false;
            if (pi >= 0) {
                isArr = callerFrame->isArray[pi];
                existingArr = callerFrame->arrays[pi];
                isUntyped = !isArr && callerFrame->scalars[pi].kind == AWK_V_UNINIT;
            } else {
                AwkVar *gv = awkFindGlobal(argNode->str);
                isArr = gv && gv->isArray;
                existingArr = gv ? gv->arr : NULL;
                isUntyped = (gv == NULL);
            }
            if (isArr && existingArr) {
                fr.arrays[i] = existingArr;
                fr.isArray[i] = true;
                fr.ownsArray[i] = false;
                continue;
            }
            if (isUntyped && fn->paramIsArray && fn->paramIsArray[i]) {
                AwkArray *newArr = awkGetArrayFor(argNode->str);
                fr.arrays[i] = newArr;
                fr.isArray[i] = true;
                fr.ownsArray[i] = false;
                continue;
            }
        }
        AwkValue v = awkEval(argNode);
        fr.scalars[i] = v;
    }

    if (gInterp.frameDepth == gInterp.frameCap) {
        gInterp.frameCap = gInterp.frameCap ? gInterp.frameCap * 2 : 16;
        gInterp.frames = (AwkFrame *)realloc(gInterp.frames, sizeof(AwkFrame) * (size_t)gInterp.frameCap);
    }
    gInterp.frames[gInterp.frameDepth++] = fr;

    AwkValue savedReturn = gInterp.returnValue;
    gInterp.returnValue = awkValUninit();
    AwkSignal sig = awkExec(fn->body);
    AwkValue result = (sig == AWK_SIG_RETURN) ? gInterp.returnValue : awkValUninit();
    if (sig != AWK_SIG_RETURN) awkValFree(&gInterp.returnValue);
    gInterp.returnValue = savedReturn;

    gInterp.frameDepth--;
    AwkFrame *popped = &gInterp.frames[gInterp.frameDepth];
    for (int i = 0; i < popped->paramCount; ++i) {
        awkValFree(&popped->scalars[i]);
        if (popped->ownsArray[i] && popped->arrays[i]) {
            awkArrayClear(popped->arrays[i]);
            free(popped->arrays[i]->buckets);
            free(popped->arrays[i]);
        }
    }
    free(popped->scalars);
    free(popped->arrays);
    free(popped->isArray);
    free(popped->ownsArray);

    if (sig == AWK_SIG_EXIT) {
        /* propagate exit by re-raising after unwinding this call --
         * handled by caller checking a sticky flag */
        gInterp.exiting = true;
    }
    return result;
}

/* ---------------- Lvalue helpers ---------------- */

static int awkSubscriptKey(AwkNode *n, char *buf, size_t bufSize) {
    const char *subsep = awkGetVarStr("SUBSEP");
    buf[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < n->listCount; ++i) {
        AwkValue v = awkEval(n->list[i]);
        char *s = awkToStrFmt(&v, "%.6g");
        awkValFree(&v);
        size_t sl = strlen(s);
        size_t sepl = (i > 0) ? strlen(subsep) : 0;
        if (used + sl + sepl < bufSize) {
            if (i > 0) { memcpy(buf + used, subsep, sepl); used += sepl; }
            memcpy(buf + used, s, sl); used += sl;
            buf[used] = '\0';
        }
        free(s);
    }
    return (int)used;
}

static AwkValue awkEvalLvalueCurrent(AwkNode *lv) {
    if (lv->kind == AWK_E_FIELD) {
        AwkValue idxV = awkEval(lv->a);
        int idx = (int)awkToNum(&idxV);
        awkValFree(&idxV);
        return awkValStrNum(awkGetField(idx));
    }
    if (lv->kind == AWK_E_VAR) {
        return awkGetScalar(lv->str);
    }
    if (lv->kind == AWK_E_ARRAYREF) {
        char key[512];
        awkSubscriptKey(lv, key, sizeof(key));
        AwkArray *arr = awkGetArrayFor(lv->str);
        AwkArrayEntry *e = awkArrayGetOrCreate(arr, key);
        return awkValCopy(&e->val);
    }
    return awkEval(lv);
}

static void awkAssignLvalue(AwkNode *lv, AwkValue val) {
    if (lv->kind == AWK_E_FIELD) {
        AwkValue idxV = awkEval(lv->a);
        int idx = (int)awkToNum(&idxV);
        awkValFree(&idxV);
        if (idx == 0) {
            char *s = awkToStrFmt(&val, "%.6g");
            awkSetField(0, s);
            free(s);
        } else {
            char *s = awkToStrFmt(&val, "%.6g");
            awkSetField(idx, s);
            free(s);
        }
        awkValFree(&val);
        return;
    }
    if (lv->kind == AWK_E_VAR) {
        if (strcmp(lv->str, "NF") == 0) {
            int nf = (int)awkToNum(&val);
            awkValFree(&val);
            awkSetNF(nf);
            return;
        }
        awkSetScalar(lv->str, val);
        return;
    }
    if (lv->kind == AWK_E_ARRAYREF) {
        char key[512];
        awkSubscriptKey(lv, key, sizeof(key));
        AwkArray *arr = awkGetArrayFor(lv->str);
        AwkArrayEntry *e = awkArrayGetOrCreate(arr, key);
        awkValFree(&e->val);
        e->val = val;
        return;
    }
    awkValFree(&val);
}

/* ---------------- getline ---------------- */

static AwkValue awkEvalGetline(AwkNode *n) {
    char *line = NULL;
    bool ok = false;
    if (n->glSrc == AWK_GL_NONE) {
        ok = awkNextMainRecord(&line);
        if (ok) {
            awkSetScalar("NR", awkValNum(awkGetVarNum("NR") + 1));
            awkSetScalar("FNR", awkValNum(awkGetVarNum("FNR") + 1));
        }
    } else if (n->glSrc == AWK_GL_FILE) {
        AwkValue fv = awkEval(n->b);
        char *fname = awkToStrFmt(&fv, "%.6g");
        awkValFree(&fv);
        FILE *fp = awkOpenInputStream(fname, false);
        free(fname);
        if (fp) ok = awkGetlineFillLine(fp, &line);
        if (ok && !n->a) awkSetScalar("NR", awkValNum(awkGetVarNum("NR") + 1));
    } else { /* CMD */
        AwkValue cv = awkEval(n->b);
        char *cmd = awkToStrFmt(&cv, "%.6g");
        awkValFree(&cv);
        FILE *fp = awkOpenInputStream(cmd, true);
        free(cmd);
        if (fp) ok = awkGetlineFillLine(fp, &line);
        if (ok) {
            awkSetScalar("NR", awkValNum(awkGetVarNum("NR") + 1));
        }
    }
    if (!ok) {
        free(line);
        return awkValNum(0);
    }
    if (n->a) {
        awkAssignLvalue(n->a, awkValStrNum(line));
    } else {
        awkSetRecord(line);
    }
    free(line);
    return awkValNum(1);
}

/* ---------------- Expression evaluation ---------------- */

static AwkValue awkEval(AwkNode *n) {
    switch (n->kind) {
        case AWK_E_NUM: return awkValNum(n->num);
        case AWK_E_STR: return awkValStr(n->str);
        case AWK_E_REGEX: {
            regex_t re;
            bool matched = false;
            if (awkRegexCompile(&re, n->str)) {
                matched = regexec(&re, awkGetField(0), 0, NULL, 0) == 0;
                regfree(&re);
            }
            return awkValNum(matched ? 1 : 0);
        }
        case AWK_E_VAR: return awkGetScalar(n->str);
        case AWK_E_FIELD: {
            AwkValue idxV = awkEval(n->a);
            int idx = (int)awkToNum(&idxV);
            awkValFree(&idxV);
            return awkValStrNum(awkGetField(idx));
        }
        case AWK_E_ARRAYREF: {
            char key[512];
            awkSubscriptKey(n, key, sizeof(key));
            AwkArray *arr = awkGetArrayFor(n->str);
            AwkArrayEntry *e = awkArrayGetOrCreate(arr, key);
            return awkValCopy(&e->val);
        }
        case AWK_E_GROUP:
            return awkEval(n->list[0]);
        case AWK_E_ASSIGN: {
            AwkValue rhs;
            if (n->op == AWK_TOK_ASSIGN) {
                rhs = awkEval(n->b);
            } else {
                AwkValue cur = awkEvalLvalueCurrent(n->a);
                AwkValue rv = awkEval(n->b);
                double a = awkToNum(&cur), b = awkToNum(&rv);
                awkValFree(&cur); awkValFree(&rv);
                double r;
                switch (n->op) {
                    case AWK_TOK_ADD_ASSIGN: r = a + b; break;
                    case AWK_TOK_SUB_ASSIGN: r = a - b; break;
                    case AWK_TOK_MUL_ASSIGN: r = a * b; break;
                    case AWK_TOK_DIV_ASSIGN: r = a / b; break;
                    case AWK_TOK_MOD_ASSIGN: r = fmod(a, b); break;
                    case AWK_TOK_POW_ASSIGN: r = pow(a, b); break;
                    default: r = b; break;
                }
                rhs = awkValNum(r);
            }
            AwkValue copy = awkValCopy(&rhs);
            awkAssignLvalue(n->a, rhs);
            return copy;
        }
        case AWK_E_TERNARY: {
            AwkValue c = awkEval(n->a);
            bool t = awkIsTrue(&c);
            awkValFree(&c);
            return t ? awkEval(n->b) : awkEval(n->c);
        }
        case AWK_E_OR: {
            AwkValue a = awkEval(n->a);
            bool at = awkIsTrue(&a);
            awkValFree(&a);
            if (at) return awkValNum(1);
            AwkValue b = awkEval(n->b);
            bool bt = awkIsTrue(&b);
            awkValFree(&b);
            return awkValNum(bt ? 1 : 0);
        }
        case AWK_E_AND: {
            AwkValue a = awkEval(n->a);
            bool at = awkIsTrue(&a);
            awkValFree(&a);
            if (!at) return awkValNum(0);
            AwkValue b = awkEval(n->b);
            bool bt = awkIsTrue(&b);
            awkValFree(&b);
            return awkValNum(bt ? 1 : 0);
        }
        case AWK_E_IN: {
            char key[512];
            const char *subsep = awkGetVarStr("SUBSEP");
            key[0] = '\0';
            size_t used = 0;
            for (int i = 0; i < n->listCount; ++i) {
                AwkValue v = awkEval(n->list[i]);
                char *s = awkToStrFmt(&v, "%.6g");
                awkValFree(&v);
                size_t sl = strlen(s);
                size_t sepl = (i > 0) ? strlen(subsep) : 0;
                if (used + sl + sepl < sizeof(key)) {
                    if (i > 0) { memcpy(key + used, subsep, sepl); used += sepl; }
                    memcpy(key + used, s, sl); used += sl;
                    key[used] = '\0';
                }
                free(s);
            }
            AwkArray *arr = awkGetArrayFor(n->str);
            AwkArrayEntry *e = awkArrayFind(arr, key);
            return awkValNum(e ? 1 : 0);
        }
        case AWK_E_MATCH: {
            AwkValue sv = awkEval(n->a);
            char *s = awkToStrFmt(&sv, "%.6g");
            awkValFree(&sv);
            char *pattern;
            if (n->b->kind == AWK_E_REGEX) pattern = strdup(n->b->str);
            else { AwkValue pv = awkEval(n->b); pattern = awkToStrFmt(&pv, "%.6g"); awkValFree(&pv); }
            regex_t re;
            bool matched = false;
            if (awkRegexCompile(&re, pattern)) {
                matched = regexec(&re, s, 0, NULL, 0) == 0;
                regfree(&re);
            }
            free(s); free(pattern);
            bool result = n->op ? !matched : matched;
            return awkValNum(result ? 1 : 0);
        }
        case AWK_E_CMP: {
            AwkValue a = awkEval(n->a);
            AwkValue b = awkEval(n->b);
            int c = awkCompare(&a, &b, awkGetVarStr("CONVFMT"));
            awkValFree(&a); awkValFree(&b);
            bool r;
            switch (n->op) {
                case AWK_TOK_LT: r = c < 0; break;
                case AWK_TOK_LE: r = c <= 0; break;
                case AWK_TOK_GT: r = c > 0; break;
                case AWK_TOK_GE: r = c >= 0; break;
                case AWK_TOK_EQ: r = c == 0; break;
                case AWK_TOK_NE: r = c != 0; break;
                default: r = false; break;
            }
            return awkValNum(r ? 1 : 0);
        }
        case AWK_E_CONCAT: {
            AwkValue a = awkEval(n->a);
            AwkValue b = awkEval(n->b);
            char *sa = awkToStrFmt(&a, awkGetVarStr("CONVFMT"));
            char *sb = awkToStrFmt(&b, awkGetVarStr("CONVFMT"));
            awkValFree(&a); awkValFree(&b);
            size_t la = strlen(sa), lb = strlen(sb);
            char *r = (char *)malloc(la + lb + 1);
            memcpy(r, sa, la);
            memcpy(r + la, sb, lb);
            r[la + lb] = '\0';
            free(sa); free(sb);
            AwkValue rv = awkValStr(r);
            free(r);
            return rv;
        }
        case AWK_E_BINOP: {
            AwkValue a = awkEval(n->a);
            AwkValue b = awkEval(n->b);
            double da = awkToNum(&a), db = awkToNum(&b);
            awkValFree(&a); awkValFree(&b);
            double r;
            switch (n->op) {
                case AWK_TOK_PLUS: r = da + db; break;
                case AWK_TOK_MINUS: r = da - db; break;
                case AWK_TOK_STAR: r = da * db; break;
                case AWK_TOK_SLASH: r = da / db; break;
                case AWK_TOK_PERCENT: r = fmod(da, db); break;
                case AWK_TOK_CARET: r = pow(da, db); break;
                default: r = 0; break;
            }
            return awkValNum(r);
        }
        case AWK_E_UNARY: {
            if (n->op == AWK_TOK_NOT) {
                AwkValue v = awkEval(n->a);
                bool t = awkIsTrue(&v);
                awkValFree(&v);
                return awkValNum(t ? 0 : 1);
            }
            AwkValue v = awkEval(n->a);
            double d = awkToNum(&v);
            awkValFree(&v);
            return awkValNum(n->op == AWK_TOK_MINUS ? -d : d);
        }
        case AWK_E_PREINCR: case AWK_E_PREDECR: {
            AwkValue cur = awkEvalLvalueCurrent(n->a);
            double d = awkToNum(&cur) + (n->kind == AWK_E_PREINCR ? 1 : -1);
            awkValFree(&cur);
            awkAssignLvalue(n->a, awkValNum(d));
            return awkValNum(d);
        }
        case AWK_E_POSTINCR: case AWK_E_POSTDECR: {
            AwkValue cur = awkEvalLvalueCurrent(n->a);
            double d = awkToNum(&cur);
            awkValFree(&cur);
            awkAssignLvalue(n->a, awkValNum(d + (n->kind == AWK_E_POSTINCR ? 1 : -1)));
            return awkValNum(d);
        }
        case AWK_E_CALL:
            return n->isBuiltin ? awkCallBuiltin(n) : awkCallUser(n);
        case AWK_E_GETLINE:
            return awkEvalGetline(n);
        default:
            return awkValUninit();
    }
}

/* ---------------- print/printf output helpers ---------------- */

static FILE *awkResolveOutput(AwkNode *n) {
    if (n->redir == AWK_REDIR_NONE) return stdout;
    AwkValue v = awkEval(n->a);
    char *target = awkToStrFmt(&v, "%.6g");
    awkValFree(&v);
    FILE *fp = awkOpenOutputStream(target, n->redir);
    if (!fp) fprintf(stderr, "awk: cannot open '%s' for output\n", target);
    free(target);
    return fp ? fp : stdout;
}

static void awkDoPrint(AwkNode *n) {
    FILE *out = awkResolveOutput(n);
    const char *ofs = awkGetVarStr("OFS");
    const char *ors = awkGetVarStr("ORS");
    if (n->listCount == 0) {
        fputs(awkGetField(0), out);
    } else {
        const char *ofmt = awkGetVarStr("OFMT");
        for (int i = 0; i < n->listCount; ++i) {
            if (i > 0) fputs(ofs, out);
            AwkValue v = awkEval(n->list[i]);
            char *s = awkToStrFmt(&v, ofmt);
            fputs(s, out);
            free(s);
            awkValFree(&v);
        }
    }
    fputs(ors, out);
}

static void awkDoPrintf(AwkNode *n) {
    if (n->listCount == 0) return;
    FILE *out = awkResolveOutput(n);
    AwkValue fv = awkEval(n->list[0]);
    char *fmt = awkToStrFmt(&fv, "%.6g");
    awkValFree(&fv);
    char *result = awkSprintfImpl(fmt, n->list, n->listCount, 1);
    fputs(result, out);
    free(result);
    free(fmt);
}

/* ---------------- Statement execution ---------------- */

static AwkSignal awkExec(AwkNode *n) {
    if (!n) return AWK_SIG_NORMAL;
    switch (n->kind) {
        case AWK_S_BLOCK: {
            for (int i = 0; i < n->listCount; ++i) {
                AwkSignal sig = awkExec(n->list[i]);
                if (sig != AWK_SIG_NORMAL) return sig;
            }
            return AWK_SIG_NORMAL;
        }
        case AWK_S_EXPR: {
            AwkValue v = awkEval(n->a);
            awkValFree(&v);
            return AWK_SIG_NORMAL;
        }
        case AWK_S_PRINT: awkDoPrint(n); return AWK_SIG_NORMAL;
        case AWK_S_PRINTF: awkDoPrintf(n); return AWK_SIG_NORMAL;
        case AWK_S_IF: {
            AwkValue c = awkEval(n->a);
            bool t = awkIsTrue(&c);
            awkValFree(&c);
            if (t) return awkExec(n->b);
            if (n->c) return awkExec(n->c);
            return AWK_SIG_NORMAL;
        }
        case AWK_S_WHILE: {
            for (;;) {
                AwkValue c = awkEval(n->a);
                bool t = awkIsTrue(&c);
                awkValFree(&c);
                if (!t) break;
                AwkSignal sig = awkExec(n->b);
                if (sig == AWK_SIG_BREAK) break;
                if (sig == AWK_SIG_CONTINUE) continue;
                if (sig != AWK_SIG_NORMAL) return sig;
            }
            return AWK_SIG_NORMAL;
        }
        case AWK_S_DOWHILE: {
            for (;;) {
                AwkSignal sig = awkExec(n->b);
                if (sig == AWK_SIG_BREAK) break;
                if (sig != AWK_SIG_NORMAL && sig != AWK_SIG_CONTINUE) return sig;
                AwkValue c = awkEval(n->a);
                bool t = awkIsTrue(&c);
                awkValFree(&c);
                if (!t) break;
            }
            return AWK_SIG_NORMAL;
        }
        case AWK_S_FOR: {
            if (n->a) { AwkSignal s = awkExec(n->a); if (s != AWK_SIG_NORMAL) return s; }
            for (;;) {
                if (n->b) {
                    AwkValue c = awkEval(n->b);
                    bool t = awkIsTrue(&c);
                    awkValFree(&c);
                    if (!t) break;
                }
                AwkSignal sig = awkExec(n->list[0]);
                if (sig == AWK_SIG_BREAK) break;
                if (sig != AWK_SIG_NORMAL && sig != AWK_SIG_CONTINUE) return sig;
                if (n->c) { AwkSignal s2 = awkExec(n->c); if (s2 != AWK_SIG_NORMAL) return s2; }
            }
            return AWK_SIG_NORMAL;
        }
        case AWK_S_FORIN: {
            AwkArray *arr = awkGetArrayFor(n->str2);
            /* Snapshot keys first since the body may mutate the array. */
            int cnt = arr->count;
            char **keys = (char **)malloc(sizeof(char *) * (size_t)(cnt > 0 ? cnt : 1));
            int ki = 0;
            for (int b = 0; b < arr->bucketCount; ++b) {
                for (AwkArrayEntry *e = arr->buckets[b]; e; e = e->next) {
                    keys[ki++] = strdup(e->key);
                }
            }
            AwkSignal result = AWK_SIG_NORMAL;
            AwkNode varNode;
            memset(&varNode, 0, sizeof(varNode));
            varNode.kind = AWK_E_VAR;
            varNode.str = n->str;
            for (int i = 0; i < ki; ++i) {
                awkAssignLvalue(&varNode, awkValStrNum(keys[i]));
                AwkSignal sig = awkExec(n->a);
                if (sig == AWK_SIG_BREAK) break;
                if (sig != AWK_SIG_NORMAL && sig != AWK_SIG_CONTINUE) { result = sig; break; }
            }
            for (int i = 0; i < ki; ++i) free(keys[i]);
            free(keys);
            return result;
        }
        case AWK_S_BREAK: return AWK_SIG_BREAK;
        case AWK_S_CONTINUE: return AWK_SIG_CONTINUE;
        case AWK_S_NEXT: return AWK_SIG_NEXT;
        case AWK_S_NEXTFILE: return AWK_SIG_NEXTFILE;
        case AWK_S_EXIT: {
            if (n->a) {
                AwkValue v = awkEval(n->a);
                gInterp.exitCode = (int)awkToNum(&v);
                awkValFree(&v);
            }
            gInterp.exiting = true;
            return AWK_SIG_EXIT;
        }
        case AWK_S_RETURN: {
            awkValFree(&gInterp.returnValue);
            gInterp.returnValue = n->a ? awkEval(n->a) : awkValUninit();
            return AWK_SIG_RETURN;
        }
        case AWK_S_DELETE: {
            char key[512];
            awkSubscriptKey(n, key, sizeof(key));
            AwkArray *arr = awkGetArrayFor(n->str);
            awkArrayDelete(arr, key);
            return AWK_SIG_NORMAL;
        }
        case AWK_S_DELETE_ALL: {
            AwkArray *arr = awkGetArrayFor(n->str);
            awkArrayClear(arr);
            return AWK_SIG_NORMAL;
        }
        default:
            return AWK_SIG_NORMAL;
    }
}

/* ---------------- Main record reading ---------------- */

static bool awkReadRecordFromFile(FILE *fp, char **outLine) {
    const char *rs = awkGetVarStr("RS");
    if (strcmp(rs, "") == 0) {
        /* paragraph mode: records separated by one-or-more blank lines */
        gAwkParagraphMode = true;
        char *buf = NULL; size_t cap = 0, len = 0;
        int c;
        /* skip leading blank lines. Uses ungetc (not ftell/fseek) for the
         * one-character lookahead-and-pushback so this works on
         * non-seekable streams too -- a pipe (the common `cmd | awk`
         * case) fails ftell/fseek silently, which was a real bug caught
         * by testing this exact scenario: the peeked byte was lost,
         * corrupting the first record of every paragraph read from a
         * pipe. */
        for (;;) {
            c = fgetc(fp);
            if (c == EOF) return false;
            if (c == '\n') continue;
            ungetc(c, fp);
            break;
        }
        bool any = false;
        int blankRun = 0;
        while ((c = fgetc(fp)) != EOF) {
            if (c == '\n') {
                blankRun++;
                if (blankRun >= 2) {
                    /* consume further blank lines */
                    for (;;) {
                        int c2 = fgetc(fp);
                        if (c2 == EOF) break;
                        if (c2 == '\n') continue;
                        ungetc(c2, fp);
                        break;
                    }
                    break;
                }
                if (len + 1 >= cap) { cap = cap ? cap * 2 : 256; buf = (char *)realloc(buf, cap); }
                buf[len++] = '\n';
                buf[len] = '\0';
                any = true;
                continue;
            }
            if (blankRun == 1) {
                /* single newline followed by real content: keep as-is */
            }
            blankRun = 0;
            if (len + 1 >= cap) { cap = cap ? cap * 2 : 256; buf = (char *)realloc(buf, cap); }
            buf[len++] = (char)c;
            buf[len] = '\0';
            any = true;
        }
        if (!any) { free(buf); return false; }
        while (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
        *outLine = buf;
        return true;
    }
    gAwkParagraphMode = false;
    if (strlen(rs) == 1) {
        char sep = rs[0];
        char *buf = NULL; size_t cap = 0, len = 0;
        int c;
        bool any = false;
        while ((c = fgetc(fp)) != EOF) {
            any = true;
            if ((char)c == sep) break;
            if (len + 1 >= cap) { cap = cap ? cap * 2 : 256; buf = (char *)realloc(buf, cap); }
            buf[len++] = (char)c;
            buf[len] = '\0';
        }
        if (!any) { free(buf); return false; }
        *outLine = buf ? buf : strdup("");
        return true;
    }
    /* multi-char RS: treated as ERE */
    regex_t re;
    bool haveRe = awkRegexCompile(&re, rs);
    char *buf = NULL; size_t cap = 0, len = 0;
    int c;
    bool any = false;
    while ((c = fgetc(fp)) != EOF) {
        any = true;
        if (len + 1 >= cap) { cap = cap ? cap * 2 : 256; buf = (char *)realloc(buf, cap); }
        buf[len++] = (char)c;
        buf[len] = '\0';
        if (haveRe) {
            regmatch_t m;
            if (regexec(&re, buf, 1, &m, 0) == 0 && (size_t)m.rm_eo == len && m.rm_so != m.rm_eo) {
                buf[m.rm_so] = '\0';
                if (haveRe) regfree(&re);
                *outLine = buf;
                return true;
            }
        }
    }
    if (haveRe) regfree(&re);
    if (!any) { free(buf); return false; }
    *outLine = buf;
    return true;
}

static bool awkGetlineFillLine(FILE *fp, char **outLine) {
    return awkReadRecordFromFile(fp, outLine);
}

static bool awkLooksLikeAssignment(const char *s, char **outName, char **outVal) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s) return false;
    for (const char *p = s; p < eq; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '_')) return false;
    }
    if (isdigit((unsigned char)s[0])) return false;
    *outName = strndup(s, (size_t)(eq - s));
    *outVal = strdup(eq + 1);
    return true;
}

static bool awkOpenNextFile(void) {
    while (gInterp.argIndex < gInterp.argc) {
        const char *arg = gInterp.argv[gInterp.argIndex++];
        char *name = NULL, *val = NULL;
        if (awkLooksLikeAssignment(arg, &name, &val)) {
            awkSetScalar(name, awkValStrNum(val));
            free(name); free(val);
            continue;
        }
        gInterp.anyFileOpened = true;
        awkSetScalar("FILENAME", awkValStr(arg));
        awkSetScalar("FNR", awkValNum(0));
        if (strcmp(arg, "-") == 0) {
            gInterp.curFile = stdin;
            gInterp.curFileIsOwned = false;
        } else {
            FILE *fp = fopen(arg, "r");
            if (!fp) {
                fprintf(stderr, "awk: can't open file %s\n", arg);
                continue;
            }
            gInterp.curFile = fp;
            gInterp.curFileIsOwned = true;
        }
        return true;
    }
    return false;
}

static bool awkNextMainRecord(char **outLine) {
    for (;;) {
        if (!gInterp.curFile) {
            if (!awkOpenNextFile()) {
                if (!gInterp.anyFileOpened) {
                    gInterp.curFile = stdin;
                    gInterp.curFileIsOwned = false;
                    gInterp.anyFileOpened = true;
                    awkSetScalar("FILENAME", awkValStr(""));
                    awkSetScalar("FNR", awkValNum(0));
                } else {
                    return false;
                }
            }
        }
        char *line = NULL;
        if (awkReadRecordFromFile(gInterp.curFile, &line)) {
            *outLine = line;
            return true;
        }
        if (gInterp.curFileIsOwned) fclose(gInterp.curFile);
        gInterp.curFile = NULL;
        if (gInterp.argIndex >= gInterp.argc && gInterp.anyFileOpened) {
            /* if we already fell back to stdin-with-no-files, don't loop forever */
            static bool stdinDone = false;
            if (stdinDone) return false;
            stdinDone = true;
        }
    }
}

/* ---------------- Range pattern state ---------------- */

/* ---------------- Program driver ---------------- */

/* Static usage analysis: does `name` appear in an array-only context
 * (subscripted, `in`, delete, for-in, or split()'s 2nd arg) anywhere in
 * this subtree? Used to decide, for a never-yet-used bare variable
 * passed as a function argument, whether it should be auto-vivified as
 * an array and aliased (matching how a function that fills an
 * uninitialized array parameter is expected to work) rather than passed
 * as a fresh scalar by value. */
static bool awkNodeUsesNameAsArray(AwkNode *n, const char *name) {
    if (!n) return false;
    bool direct = false;
    switch (n->kind) {
        case AWK_E_ARRAYREF:
        case AWK_E_IN:
        case AWK_S_DELETE:
        case AWK_S_DELETE_ALL:
            if (n->str && strcmp(n->str, name) == 0) direct = true;
            break;
        case AWK_S_FORIN:
            if (n->str2 && strcmp(n->str2, name) == 0) direct = true;
            break;
        case AWK_E_CALL:
            if (n->isBuiltin && strcmp(n->str, "split") == 0 && n->listCount >= 2 &&
                n->list[1]->kind == AWK_E_VAR && n->list[1]->str &&
                strcmp(n->list[1]->str, name) == 0) {
                direct = true;
            }
            break;
        default:
            break;
    }
    if (direct) return true;
    if (awkNodeUsesNameAsArray(n->a, name)) return true;
    if (awkNodeUsesNameAsArray(n->b, name)) return true;
    if (awkNodeUsesNameAsArray(n->c, name)) return true;
    for (int i = 0; i < n->listCount; ++i) {
        if (n->list && awkNodeUsesNameAsArray(n->list[i], name)) return true;
    }
    return false;
}

static AwkFunc *awkFindFunc(const char *name);

/* One level of call-forwarding: `name` is array-used if it's passed bare
 * to another user function at a parameter position that function itself
 * uses as an array. Callers iterate this to a fixed point since
 * functions can reference each other in any order. */
static bool awkNodeForwardsNameAsArrayCall(AwkNode *n, const char *name) {
    if (!n) return false;
    if (n->kind == AWK_E_CALL && !n->isBuiltin) {
        AwkFunc *callee = awkFindFunc(n->str);
        if (callee) {
            for (int i = 0; i < n->listCount && i < callee->paramCount; ++i) {
                if (n->list[i]->kind == AWK_E_VAR && n->list[i]->str &&
                    strcmp(n->list[i]->str, name) == 0 &&
                    callee->paramIsArray && callee->paramIsArray[i]) {
                    return true;
                }
            }
        }
    }
    if (awkNodeForwardsNameAsArrayCall(n->a, name)) return true;
    if (awkNodeForwardsNameAsArrayCall(n->b, name)) return true;
    if (awkNodeForwardsNameAsArrayCall(n->c, name)) return true;
    for (int i = 0; i < n->listCount; ++i) {
        if (n->list && awkNodeForwardsNameAsArrayCall(n->list[i], name)) return true;
    }
    return false;
}

static void awkAnalyzeFunctionArrayParams(void) {
    for (int i = 0; i < gInterp.funcCount; ++i) {
        AwkFunc *f = &gInterp.funcs[i];
        f->paramIsArray = (bool *)calloc((size_t)(f->paramCount > 0 ? f->paramCount : 1), sizeof(bool));
        for (int p = 0; p < f->paramCount; ++p) {
            f->paramIsArray[p] = awkNodeUsesNameAsArray(f->body, f->params[p]);
        }
    }
    for (int iter = 0; iter < 8; ++iter) {
        bool changed = false;
        for (int i = 0; i < gInterp.funcCount; ++i) {
            AwkFunc *f = &gInterp.funcs[i];
            for (int p = 0; p < f->paramCount; ++p) {
                if (f->paramIsArray[p]) continue;
                if (awkNodeForwardsNameAsArrayCall(f->body, f->params[p])) {
                    f->paramIsArray[p] = true;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }
}

static void awkCollectFunctions(AwkProgram *prog) {
    int cnt = 0;
    for (int i = 0; i < prog->itemCount; ++i) if (prog->items[i]->kind == AWK_ITEM_FUNC) cnt++;
    gInterp.funcs = (AwkFunc *)calloc((size_t)(cnt > 0 ? cnt : 1), sizeof(AwkFunc));
    gInterp.funcCount = 0;
    for (int i = 0; i < prog->itemCount; ++i) {
        AwkNode *it = prog->items[i];
        if (it->kind != AWK_ITEM_FUNC) continue;
        AwkFunc *f = &gInterp.funcs[gInterp.funcCount++];
        f->name = it->str;
        f->params = it->params;
        f->paramCount = it->paramCount;
        f->body = it->a;
    }
    awkAnalyzeFunctionArrayParams();
}

static void awkInitBuiltinVars(const char *fsOverride) {
    awkSetScalar("FS", fsOverride ? awkValStr(fsOverride) : awkValStr(" "));
    awkSetScalar("OFS", awkValStr(" "));
    awkSetScalar("ORS", awkValStr("\n"));
    awkSetScalar("RS", awkValStr("\n"));
    awkSetScalar("NR", awkValNum(0));
    awkSetScalar("NF", awkValNum(0));
    awkSetScalar("FNR", awkValNum(0));
    awkSetScalar("SUBSEP", awkValStr("\034"));
    awkSetScalar("CONVFMT", awkValStr("%.6g"));
    awkSetScalar("OFMT", awkValStr("%.6g"));
    awkSetScalar("FILENAME", awkValStr(""));
    awkSetScalar("RSTART", awkValNum(0));
    awkSetScalar("RLENGTH", awkValNum(-1));
}

extern char **environ;

static void awkPopulateEnviron(void) {
    AwkArray *env = awkGetArrayFor("ENVIRON");
    for (char **e = environ; e && *e; ++e) {
        char *eq = strchr(*e, '=');
        if (!eq) continue;
        char *name = strndup(*e, (size_t)(eq - *e));
        AwkArrayEntry *ent = awkArrayGetOrCreate(env, name);
        awkValFree(&ent->val);
        ent->val = awkValStrNum(eq + 1);
        free(name);
    }
}

int awkRunProgram(AwkProgram *prog, int argc, char **argv, int argStart,
                   char **preAssigns, int preAssignCount, const char *fsOverride) {
    memset(&gInterp, 0, sizeof(gInterp));
    gInterp.prog = prog;
    gInterp.randState = 1;
    gInterp.record = strdup("");

    awkInitBuiltinVars(fsOverride);
    awkCollectFunctions(prog);
    awkPopulateEnviron();

    AwkArray *argvArr = awkGetArrayFor("ARGV");
    char key0[16] = "0";
    AwkArrayEntry *e0 = awkArrayGetOrCreate(argvArr, key0);
    e0->val = awkValStr("awk");
    int nRealArgs = argc - argStart;
    for (int i = 0; i < nRealArgs; ++i) {
        char key[32];
        snprintf(key, sizeof(key), "%d", i + 1);
        AwkArrayEntry *e = awkArrayGetOrCreate(argvArr, key);
        awkValFree(&e->val);
        e->val = awkValStr(argv[argStart + i]);
    }
    awkSetScalar("ARGC", awkValNum(nRealArgs + 1));

    for (int i = 0; i < preAssignCount; ++i) {
        char *name = NULL, *val = NULL;
        if (awkLooksLikeAssignment(preAssigns[i], &name, &val)) {
            awkSetScalar(name, awkValStrNum(val));
            free(name); free(val);
        }
    }

    gInterp.argv = argv + argStart;
    gInterp.argc = nRealArgs;
    gInterp.argIndex = 0;

    bool hasMainOrEnd = false;
    for (int i = 0; i < prog->itemCount; ++i) {
        AwkNode *it = prog->items[i];
        if (it->kind == AWK_ITEM_RULE && it->patKind != AWK_PAT_BEGIN) hasMainOrEnd = true;
    }
    gInterp.rangeActiveByRule = (bool *)calloc((size_t)(prog->itemCount > 0 ? prog->itemCount : 1), sizeof(bool));

    /* BEGIN */
    for (int i = 0; i < prog->itemCount && !gInterp.exiting; ++i) {
        AwkNode *it = prog->items[i];
        if (it->kind == AWK_ITEM_RULE && it->patKind == AWK_PAT_BEGIN) {
            awkExec(it->c);
        }
    }

    if (hasMainOrEnd && !gInterp.exiting) {
        char *line;
        while (awkNextMainRecord(&line)) {
            awkSetScalar("NR", awkValNum(awkGetVarNum("NR") + 1));
            awkSetScalar("FNR", awkValNum(awkGetVarNum("FNR") + 1));
            awkSetRecord(line);
            free(line);

            bool doNext = false;
            bool doNextFile = false;
            for (int i = 0; i < prog->itemCount; ++i) {
                AwkNode *it = prog->items[i];
                if (it->kind != AWK_ITEM_RULE) continue;
                if (it->patKind == AWK_PAT_BEGIN || it->patKind == AWK_PAT_END) continue;
                bool matched = false;
                if (it->patKind == AWK_PAT_ALWAYS) {
                    matched = true;
                } else if (it->patKind == AWK_PAT_EXPR) {
                    AwkValue v = awkEval(it->a);
                    matched = awkIsTrue(&v);
                    awkValFree(&v);
                } else if (it->patKind == AWK_PAT_RANGE) {
                    if (!gInterp.rangeActiveByRule[i]) {
                        AwkValue v1 = awkEval(it->a);
                        bool startMatch = awkIsTrue(&v1);
                        awkValFree(&v1);
                        if (startMatch) {
                            gInterp.rangeActiveByRule[i] = true;
                            matched = true;
                            AwkValue v2 = awkEval(it->b);
                            bool endMatch = awkIsTrue(&v2);
                            awkValFree(&v2);
                            if (endMatch) gInterp.rangeActiveByRule[i] = false;
                        }
                    } else {
                        matched = true;
                        AwkValue v2 = awkEval(it->b);
                        bool endMatch = awkIsTrue(&v2);
                        awkValFree(&v2);
                        if (endMatch) gInterp.rangeActiveByRule[i] = false;
                    }
                }
                if (matched) {
                    AwkSignal sig;
                    if (it->c) {
                        sig = awkExec(it->c);
                    } else {
                        awkDoPrint(&(AwkNode){.kind=AWK_S_PRINT, .redir=AWK_REDIR_NONE, .list=NULL, .listCount=0});
                        sig = AWK_SIG_NORMAL;
                    }
                    if (sig == AWK_SIG_NEXT) { doNext = true; break; }
                    if (sig == AWK_SIG_NEXTFILE) { doNextFile = true; break; }
                    if (sig == AWK_SIG_EXIT || gInterp.exiting) { gInterp.exiting = true; break; }
                }
            }
            if (gInterp.exiting) break;
            if (doNextFile) {
                if (gInterp.curFileIsOwned && gInterp.curFile) fclose(gInterp.curFile);
                gInterp.curFile = NULL;
            }
            (void)doNext;
        }
    }

    gInterp.exiting = false; /* END blocks run even after exit; only exit-inside-END is final */
    for (int i = 0; i < prog->itemCount; ++i) {
        AwkNode *it = prog->items[i];
        if (it->kind == AWK_ITEM_RULE && it->patKind == AWK_PAT_END) {
            AwkSignal sig = awkExec(it->c);
            if (sig == AWK_SIG_EXIT) break;
        }
    }

    fflush(stdout);
    awkCloseAllStreams();
    return gInterp.exitCode;
}
