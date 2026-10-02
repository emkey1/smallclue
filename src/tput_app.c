/* tput and reset, reading the terminfo database directly.
 *
 * tput prints a terminal capability -- `tput setaf 1`, `tput cup 5 10`,
 * `tput cols` -- or reports whether the terminal has one, the way ncurses'
 * tput does. It reads the compiled terminfo entry itself (both the legacy and
 * the 32-bit number formats, and the extended section with user-defined
 * capabilities such as Tc or Ss) and evaluates parameterised strings with its
 * own tparm, so it needs no curses library -- which a static SmallCLUE, or one
 * compiled into an app as host code, does not have.
 *
 * reset puts the terminal back: `stty sane`, then the terminal's reset
 * strings (rs1, rs2, rs3, falling back to is1..is3), then the cursor shown.
 */

#include "tput_app.h"
#include "stty_app.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* 44 capabilities, in compiled terminfo bool index order (ncurses 6.6's
 * boolnames; the order is append-only across releases). */
static const char *const tputCapBoolNames[] = {
    "bw", "am", "xsb", "xhp", "xenl", "eo", "gn", "hc", "km", "hs", "in",
    "da", "db", "mir", "msgr", "os", "eslok", "xt", "hz", "ul", "xon", "nxon",
    "mc5i", "chts", "nrrmc", "npc", "ndscr", "ccc", "bce", "hls", "xhpa",
    "crxm", "daisy", "xvpa", "sam", "cpix", "lpix", "OTbs", "OTns", "OTnc",
    "OTMT", "OTNL", "OTpt", "OTxr",
};
#define TPUT_BOOL_COUNT 44

/* 39 capabilities, in compiled terminfo num index order (ncurses 6.6's
 * numnames; the order is append-only across releases). */
static const char *const tputCapNumNames[] = {
    "cols", "it", "lines", "lm", "xmc", "pb", "vt", "wsl", "nlab", "lh", "lw",
    "ma", "wnum", "colors", "pairs", "ncv", "bufsz", "spinv", "spinh",
    "maddr", "mjump", "mcs", "mls", "npins", "orc", "orl", "orhi", "orvi",
    "cps", "widcs", "btns", "bitwin", "bitype", "OTug", "OTdC", "OTdN",
    "OTdB", "OTdT", "OTkn",
};
#define TPUT_NUM_COUNT 39

/* 414 capabilities, in compiled terminfo str index order (ncurses 6.6's
 * strnames; the order is append-only across releases). */
static const char *const tputCapStrNames[] = {
    "cbt", "bel", "cr", "csr", "tbc", "clear", "el", "ed", "hpa", "cmdch",
    "cup", "cud1", "home", "civis", "cub1", "mrcup", "cnorm", "cuf1", "ll",
    "cuu1", "cvvis", "dch1", "dl1", "dsl", "hd", "smacs", "blink", "bold",
    "smcup", "smdc", "dim", "smir", "invis", "prot", "rev", "smso", "smul",
    "ech", "rmacs", "sgr0", "rmcup", "rmdc", "rmir", "rmso", "rmul", "flash",
    "ff", "fsl", "is1", "is2", "is3", "if", "ich1", "il1", "ip", "kbs",
    "ktbc", "kclr", "kctab", "kdch1", "kdl1", "kcud1", "krmir", "kel", "ked",
    "kf0", "kf1", "kf10", "kf2", "kf3", "kf4", "kf5", "kf6", "kf7", "kf8",
    "kf9", "khome", "kich1", "kil1", "kcub1", "kll", "knp", "kpp", "kcuf1",
    "kind", "kri", "khts", "kcuu1", "rmkx", "smkx", "lf0", "lf1", "lf10",
    "lf2", "lf3", "lf4", "lf5", "lf6", "lf7", "lf8", "lf9", "rmm", "smm",
    "nel", "pad", "dch", "dl", "cud", "ich", "indn", "il", "cub", "cuf",
    "rin", "cuu", "pfkey", "pfloc", "pfx", "mc0", "mc4", "mc5", "rep", "rs1",
    "rs2", "rs3", "rf", "rc", "vpa", "sc", "ind", "ri", "sgr", "hts", "wind",
    "ht", "tsl", "uc", "hu", "iprog", "ka1", "ka3", "kb2", "kc1", "kc3",
    "mc5p", "rmp", "acsc", "pln", "kcbt", "smxon", "rmxon", "smam", "rmam",
    "xonc", "xoffc", "enacs", "smln", "rmln", "kbeg", "kcan", "kclo", "kcmd",
    "kcpy", "kcrt", "kend", "kent", "kext", "kfnd", "khlp", "kmrk", "kmsg",
    "kmov", "knxt", "kopn", "kopt", "kprv", "kprt", "krdo", "kref", "krfr",
    "krpl", "krst", "kres", "ksav", "kspd", "kund", "kBEG", "kCAN", "kCMD",
    "kCPY", "kCRT", "kDC", "kDL", "kslt", "kEND", "kEOL", "kEXT", "kFND",
    "kHLP", "kHOM", "kIC", "kLFT", "kMSG", "kMOV", "kNXT", "kOPT", "kPRV",
    "kPRT", "kRDO", "kRPL", "kRIT", "kRES", "kSAV", "kSPD", "kUND", "rfi",
    "kf11", "kf12", "kf13", "kf14", "kf15", "kf16", "kf17", "kf18", "kf19",
    "kf20", "kf21", "kf22", "kf23", "kf24", "kf25", "kf26", "kf27", "kf28",
    "kf29", "kf30", "kf31", "kf32", "kf33", "kf34", "kf35", "kf36", "kf37",
    "kf38", "kf39", "kf40", "kf41", "kf42", "kf43", "kf44", "kf45", "kf46",
    "kf47", "kf48", "kf49", "kf50", "kf51", "kf52", "kf53", "kf54", "kf55",
    "kf56", "kf57", "kf58", "kf59", "kf60", "kf61", "kf62", "kf63", "el1",
    "mgc", "smgl", "smgr", "fln", "sclk", "dclk", "rmclk", "cwin", "wingo",
    "hup", "dial", "qdial", "tone", "pulse", "hook", "pause", "wait", "u0",
    "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9", "op", "oc", "initc",
    "initp", "scp", "setf", "setb", "cpi", "lpi", "chr", "cvr", "defc",
    "swidm", "sdrfq", "sitm", "slm", "smicm", "snlq", "snrmq", "sshm",
    "ssubm", "ssupm", "sum", "rwidm", "ritm", "rlm", "rmicm", "rshm", "rsubm",
    "rsupm", "rum", "mhpa", "mcud1", "mcub1", "mcuf1", "mvpa", "mcuu1",
    "porder", "mcud", "mcub", "mcuf", "mcuu", "scs", "smgb", "smgbp", "smglp",
    "smgrp", "smgt", "smgtp", "sbim", "scsd", "rbim", "rcsd", "subcs",
    "supcs", "docr", "zerom", "csnm", "kmous", "minfo", "reqmp", "getm",
    "setaf", "setab", "pfxl", "devt", "csin", "s0ds", "s1ds", "s2ds", "s3ds",
    "smglr", "smgtb", "birep", "binel", "bicr", "colornm", "defbi", "endbi",
    "setcolor", "slines", "dispc", "smpch", "rmpch", "smsc", "rmsc", "pctrm",
    "scesc", "scesa", "ehhlm", "elhlm", "elohlm", "erhlm", "ethlm", "evhlm",
    "sgr1", "slength", "OTi2", "OTrs", "OTnl", "OTbc", "OTko", "OTma", "OTG2",
    "OTG3", "OTG1", "OTG4", "OTGR", "OTGL", "OTGU", "OTGD", "OTGH", "OTGV",
    "OTGC", "meml", "memu", "box1",
};
#define TPUT_STR_COUNT 414

/* -------------------------------------------------------- the entry itself */

typedef struct {
    char *names;              /* "xterm-256color|xterm with 256 colors" */
    signed char bools[TPUT_BOOL_COUNT];
    int nums[TPUT_NUM_COUNT];
    const char *strs[TPUT_STR_COUNT];
    /* The extended section: user-defined names and their values. */
    size_t extCount;
    char **extNames;
    char extKind[512];        /* 'b', 'n' or 's' per extended entry */
    int extNums[512];
    const char *extStrs[512];
    unsigned char *blob;      /* the file, which strs point into */
} TputEntry;

static int tputLe16(const unsigned char *p) {
    int v = p[0] | (p[1] << 8);
    return v >= 0x8000 ? v - 0x10000 : v;
}

static int tputLe32(const unsigned char *p) {
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (int32_t)v;
}

static unsigned char *tputReadFile(const char *path, size_t *sizeOut) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    size_t cap = 8192, len = 0;
    unsigned char *buf = malloc(cap);
    while (buf) {
        if (len == cap) {
            if (cap >= (1u << 20)) {
                free(buf);
                buf = NULL;
                break;
            }
            unsigned char *bigger = realloc(buf, cap * 2);
            if (!bigger) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = bigger;
            cap *= 2;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        if (n == 0) {
            break;
        }
        len += n;
    }
    fclose(f);
    if (buf) {
        *sizeOut = len;
    }
    return buf;
}

/* Parse a compiled entry. Returns false for anything that is not one. */
static bool tputParse(unsigned char *data, size_t size, TputEntry *e) {
    memset(e, 0, sizeof(*e));
    if (size < 12) {
        return false;
    }
    int magic = tputLe16(data);
    int numWidth;
    if (magic == 0432) {
        numWidth = 2;
    } else if (magic == 01036) {
        numWidth = 4;
    } else {
        return false;
    }
    int nameSize = tputLe16(data + 2);
    int boolCount = tputLe16(data + 4);
    int numCount = tputLe16(data + 6);
    int strCount = tputLe16(data + 8);
    int tableSize = tputLe16(data + 10);
    if (nameSize < 0 || boolCount < 0 || numCount < 0 || strCount < 0 || tableSize < 0) {
        return false;
    }
    size_t at = 12;
    if (at + (size_t)nameSize > size) {
        return false;
    }
    e->names = strndup((const char *)data + at, (size_t)nameSize);
    at += (size_t)nameSize;
    for (int i = 0; i < boolCount; i++, at++) {
        if (at >= size) {
            return false;
        }
        if (i < TPUT_BOOL_COUNT) {
            e->bools[i] = (signed char)data[at];
        }
    }
    if (at & 1) {
        at++;
    }
    for (int i = 0; i < TPUT_NUM_COUNT; i++) {
        e->nums[i] = -1;
    }
    for (int i = 0; i < numCount; i++, at += (size_t)numWidth) {
        if (at + (size_t)numWidth > size) {
            return false;
        }
        int v = numWidth == 2 ? tputLe16(data + at) : tputLe32(data + at);
        if (i < TPUT_NUM_COUNT) {
            e->nums[i] = v;
        }
    }
    size_t offsetsAt = at;
    at += (size_t)strCount * 2;
    size_t tableAt = at;
    if (tableAt + (size_t)tableSize > size) {
        return false;
    }
    for (int i = 0; i < strCount && i < TPUT_STR_COUNT; i++) {
        int off = tputLe16(data + offsetsAt + (size_t)i * 2);
        if (off >= 0 && off < tableSize) {
            e->strs[i] = (const char *)data + tableAt + off;
        }
    }
    at = tableAt + (size_t)tableSize;
    e->blob = data;

    /* The extended section, if there is one: counts, then values, then the
     * offsets of the strings and of the names, then one table of both. */
    if (at & 1) {
        at++;
    }
    if (at + 10 > size) {
        return true;
    }
    int extBools = tputLe16(data + at);
    int extNums = tputLe16(data + at + 2);
    int extStrs = tputLe16(data + at + 4);
    int extItems = tputLe16(data + at + 6);
    int extTable = tputLe16(data + at + 8);
    at += 10;
    if (extBools < 0 || extNums < 0 || extStrs < 0 || extItems < 0 || extTable < 0 ||
        extBools + extNums + extStrs > 512) {
        return true;
    }
    size_t boolsAt = at;
    at += (size_t)extBools;
    if (at & 1) {
        at++;
    }
    size_t numsAt = at;
    at += (size_t)extNums * (size_t)numWidth;
    size_t strOffsAt = at;
    at += (size_t)extStrs * 2;
    size_t nameOffsAt = at;
    int extNameCount = extBools + extNums + extStrs;
    at += (size_t)extNameCount * 2;
    size_t extTableAt = at;
    if (extTableAt + (size_t)extTable > size) {
        return true;
    }
    /* Strings come first in the table, then the names; a name's offset is
     * from the start of the names, which is just past the last string. */
    size_t namesBase = 0;
    for (int i = 0; i < extStrs; i++) {
        int off = tputLe16(data + strOffsAt + (size_t)i * 2);
        if (off >= 0) {
            const char *s = (const char *)data + extTableAt + off;
            size_t end = (size_t)off + strlen(s) + 1;
            if (end > namesBase) {
                namesBase = end;
            }
        }
    }
    e->extNames = calloc((size_t)extNameCount, sizeof(char *));
    if (!e->extNames) {
        return true;
    }
    for (int i = 0; i < extNameCount; i++) {
        int off = tputLe16(data + nameOffsAt + (size_t)i * 2);
        if (off < 0 || namesBase + (size_t)off >= (size_t)extTable) {
            continue;
        }
        e->extNames[i] = (char *)data + extTableAt + namesBase + off;
        if (i < extBools) {
            e->extKind[i] = 'b';
            e->extNums[i] = data[boolsAt + (size_t)i];
        } else if (i < extBools + extNums) {
            int k = i - extBools;
            e->extKind[i] = 'n';
            e->extNums[i] = numWidth == 2 ? tputLe16(data + numsAt + (size_t)k * 2)
                                          : tputLe32(data + numsAt + (size_t)k * 4);
        } else {
            int k = i - extBools - extNums;
            int off2 = tputLe16(data + strOffsAt + (size_t)k * 2);
            e->extKind[i] = 's';
            e->extStrs[i] = off2 >= 0 ? (const char *)data + extTableAt + off2 : NULL;
        }
    }
    e->extCount = (size_t)extNameCount;
    return true;
}

static bool tputTryDir(const char *dir, const char *term, TputEntry *e) {
    if (!dir || !*dir) {
        return false;
    }
    char path[PATH_MAX];
    /* <dir>/x/xterm, and the hashed form a case-insensitive host uses,
     * <dir>/78/xterm. */
    const char *forms[] = { "%s/%c/%s", "%s/%02x/%s" };
    for (int f = 0; f < 2; f++) {
        if (f == 0) {
            snprintf(path, sizeof(path), forms[0], dir, term[0], term);
        } else {
            snprintf(path, sizeof(path), forms[1], dir, (unsigned char)term[0], term);
        }
        size_t size = 0;
        unsigned char *data = tputReadFile(path, &size);
        if (data) {
            if (tputParse(data, size, e)) {
                return true;
            }
            free(data);
        }
    }
    return false;
}

static bool tputLoad(const char *term, TputEntry *e) {
    if (!term || !*term || strchr(term, '/') || strcmp(term, ".") == 0 || strcmp(term, "..") == 0) {
        return false;
    }
    if (tputTryDir(getenv("TERMINFO"), term, e)) {
        return true;
    }
    const char *home = getenv("HOME");
    if (home && *home) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/.terminfo", home);
        if (tputTryDir(dir, term, e)) {
            return true;
        }
    }
    static const char *const defaults[] = {
        "/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo", "/usr/lib/terminfo", NULL
    };
    const char *dirs = getenv("TERMINFO_DIRS");
    if (dirs && *dirs) {
        char *copy = strdup(dirs);
        for (char *p = copy, *next; p; p = next) {
            next = strchr(p, ':');
            if (next) {
                *next++ = '\0';
            }
            if (*p == '\0') {
                for (int i = 0; defaults[i]; i++) {
                    if (tputTryDir(defaults[i], term, e)) {
                        free(copy);
                        return true;
                    }
                }
            } else if (tputTryDir(p, term, e)) {
                free(copy);
                return true;
            }
        }
        free(copy);
    }
    for (int i = 0; defaults[i]; i++) {
        if (tputTryDir(defaults[i], term, e)) {
            return true;
        }
    }
    return false;
}

/* What a capability name is and where its value lives: 'b', 'n' or 's', or 0
 * when the terminal description has no such name at all. */
static char tputLookup(const TputEntry *e, const char *name, int *numOut, const char **strOut) {
    for (int i = 0; i < TPUT_BOOL_COUNT; i++) {
        if (strcmp(tputCapBoolNames[i], name) == 0) {
            *numOut = e->bools[i] == 1;
            return 'b';
        }
    }
    for (int i = 0; i < TPUT_NUM_COUNT; i++) {
        if (strcmp(tputCapNumNames[i], name) == 0) {
            *numOut = e->nums[i];
            return 'n';
        }
    }
    for (int i = 0; i < TPUT_STR_COUNT; i++) {
        if (strcmp(tputCapStrNames[i], name) == 0) {
            *strOut = e->strs[i];
            return 's';
        }
    }
    for (size_t i = 0; i < e->extCount; i++) {
        if (e->extNames[i] && strcmp(e->extNames[i], name) == 0) {
            if (e->extKind[i] == 's') {
                *strOut = e->extStrs[i];
            } else {
                *numOut = e->extNums[i];
            }
            return e->extKind[i];
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ tparm */

typedef struct {
    bool isString;
    long num;
    const char *str;
} TputValue;

typedef struct {
    char *buf;
    size_t len, cap;
} TputOut;

static void tputPut(TputOut *o, const char *s, size_t n) {
    if (o->len + n + 1 > o->cap) {
        size_t cap = o->cap ? o->cap : 128;
        while (o->len + n + 1 > cap) {
            cap *= 2;
        }
        char *b = realloc(o->buf, cap);
        if (!b) {
            return;
        }
        o->buf = b;
        o->cap = cap;
    }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = '\0';
}

/* Skip from just past a %t (or %e) to the matching %e or %; -- the former
 * only when STOP_AT_ELSE. Returns the position just past what was found. */
static const char *tputSkip(const char *p, bool stopAtElse) {
    int depth = 0;
    while (*p) {
        if (*p == '%' && p[1]) {
            char c = p[1];
            if (c == '?') {
                depth++;
            } else if (c == ';') {
                if (depth == 0) {
                    return p + 2;
                }
                depth--;
            } else if (c == 'e' && depth == 0 && stopAtElse) {
                return p + 2;
            }
            p += 2;
        } else {
            p++;
        }
    }
    return p;
}

/* Evaluate a parameterised string, terminfo's own little stack language. */
static char *tputTparm(const char *cap, const TputValue *params, int paramCount) {
    TputValue p[9];
    for (int i = 0; i < 9; i++) {
        p[i] = i < paramCount ? params[i] : (TputValue){ false, 0, NULL };
    }
    TputValue stack[64];
    int sp = 0;
    long dyn[26] = {0};
    static long svars[26];
    TputOut out = {0};
    tputPut(&out, "", 0);

#define PUSHN(v) do { if (sp < 64) { stack[sp].isString = false; stack[sp].num = (v); stack[sp].str = NULL; sp++; } } while (0)
#define POPN() (sp > 0 ? (stack[--sp].isString ? (long)(stack[sp].str ? strlen(stack[sp].str) : 0) : stack[sp].num) : 0)

    for (const char *s = cap; *s; ) {
        if (*s != '%') {
            tputPut(&out, s, 1);
            s++;
            continue;
        }
        s++;
        char c = *s;
        if (c == '\0') {
            break;
        }
        switch (c) {
            case '%': tputPut(&out, "%", 1); s++; break;
            case 'c': {
                char ch = (char)POPN();
                tputPut(&out, &ch, 1);
                s++;
                break;
            }
            case 's': {
                const char *str = "";
                if (sp > 0) {
                    sp--;
                    if (stack[sp].isString && stack[sp].str) {
                        str = stack[sp].str;
                    }
                }
                tputPut(&out, str, strlen(str));
                s++;
                break;
            }
            case 'p':
                if (s[1] >= '1' && s[1] <= '9') {
                    if (sp < 64) {
                        stack[sp++] = p[s[1] - '1'];
                    }
                    s += 2;
                } else {
                    s++;
                }
                break;
            case 'P':
                if (s[1] >= 'a' && s[1] <= 'z') {
                    dyn[s[1] - 'a'] = POPN();
                } else if (s[1] >= 'A' && s[1] <= 'Z') {
                    svars[s[1] - 'A'] = POPN();
                }
                s += s[1] ? 2 : 1;
                break;
            case 'g':
                if (s[1] >= 'a' && s[1] <= 'z') {
                    PUSHN(dyn[s[1] - 'a']);
                } else if (s[1] >= 'A' && s[1] <= 'Z') {
                    PUSHN(svars[s[1] - 'A']);
                }
                s += s[1] ? 2 : 1;
                break;
            case '\'':
                if (s[1] && s[2] == '\'') {
                    PUSHN((unsigned char)s[1]);
                    s += 3;
                } else {
                    s++;
                }
                break;
            case '{': {
                char *end = NULL;
                long v = strtol(s + 1, &end, 10);
                PUSHN(v);
                s = (end && *end == '}') ? end + 1 : s + 1;
                break;
            }
            case 'l': {
                long len = 0;
                if (sp > 0) {
                    sp--;
                    len = stack[sp].isString && stack[sp].str ? (long)strlen(stack[sp].str) : 0;
                }
                PUSHN(len);
                s++;
                break;
            }
            case '+': case '-': case '*': case '/': case 'm':
            case '&': case '|': case '^': case '=': case '>': case '<':
            case 'A': case 'O': {
                long b = POPN();
                long a = POPN();
                long r = 0;
                switch (c) {
                    case '+': r = a + b; break;
                    case '-': r = a - b; break;
                    case '*': r = a * b; break;
                    case '/': r = b ? a / b : 0; break;
                    case 'm': r = b ? a % b : 0; break;
                    case '&': r = a & b; break;
                    case '|': r = a | b; break;
                    case '^': r = a ^ b; break;
                    case '=': r = a == b; break;
                    case '>': r = a > b; break;
                    case '<': r = a < b; break;
                    case 'A': r = a && b; break;
                    case 'O': r = a || b; break;
                }
                PUSHN(r);
                s++;
                break;
            }
            case '!': { long a = POPN(); PUSHN(!a); s++; break; }
            case '~': { long a = POPN(); PUSHN(~a); s++; break; }
            case 'i':
                if (!p[0].isString) p[0].num++;
                if (!p[1].isString) p[1].num++;
                s++;
                break;
            case '?':
                s++;
                break;
            case 't': {
                long cond = POPN();
                s++;
                if (!cond) {
                    s = tputSkip(s, true);
                }
                break;
            }
            case 'e':
                /* Reached only after a taken then-part: skip the else. */
                s = tputSkip(s + 1, false);
                break;
            case ';':
                s++;
                break;
            default: {
                /* %[[:]flags][width[.precision]][doxXs] */
                const char *start = s;
                if (*s == ':') {
                    s++;
                }
                char fmt[32] = "%";
                size_t fl = 1;
                while (*s && strchr("-+# ", *s) && fl < sizeof(fmt) - 4) {
                    fmt[fl++] = *s++;
                }
                while (*s && (isdigit((unsigned char)*s) || *s == '.') && fl < sizeof(fmt) - 4) {
                    fmt[fl++] = *s++;
                }
                char conv = *s;
                if (!conv || !strchr("doxXs", conv)) {
                    s = start + 1;   /* not a format: drop the % */
                    break;
                }
                s++;
                char text[128];
                if (conv == 's') {
                    const char *str = "";
                    if (sp > 0) {
                        sp--;
                        if (stack[sp].isString && stack[sp].str) {
                            str = stack[sp].str;
                        }
                    }
                    fmt[fl++] = 's';
                    fmt[fl] = '\0';
                    snprintf(text, sizeof(text), fmt, str);
                } else {
                    fmt[fl++] = 'l';
                    fmt[fl++] = conv;
                    fmt[fl] = '\0';
                    long v = POPN();
                    snprintf(text, sizeof(text), fmt, v);
                }
                tputPut(&out, text, strlen(text));
                break;
            }
        }
    }
#undef PUSHN
#undef POPN
    return out.buf;
}

/* Write a capability string as tputs would, without the delays: $<5>, $<2*>
 * and the like are padding for hardware terminals and are not output. */
static void tputEmit(const char *s) {
    for (; *s; s++) {
        if (s[0] == '$' && s[1] == '<') {
            const char *end = strchr(s, '>');
            if (end) {
                s = end;
                continue;
            }
        }
        fputc(*s, stdout);
    }
}

/* -------------------------------------------------------------------- tput */

static bool tputWindowSize(int *cols, int *lines) {
    struct winsize ws;
    int fds[] = { STDOUT_FILENO, STDERR_FILENO, STDIN_FILENO };
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (ioctl(fds[i], TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
            *cols = ws.ws_col;
            *lines = ws.ws_row;
            return true;
        }
    }
    return false;
}

static bool tputLooksNumeric(const char *s) {
    if (*s == '-' || *s == '+') {
        s++;
    }
    if (!*s) {
        return false;
    }
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) {
            return false;
        }
    }
    return true;
}

/* Output the strings that initialise (or reset) the terminal: the first of
 * each pair that the entry has. */
static void tputInitStrings(const TputEntry *e, bool reset) {
    static const char *const initNames[] = { "is1", "is2", "is3" };
    static const char *const resetNames[] = { "rs1", "rs2", "rs3" };
    for (int i = 0; i < 3; i++) {
        int n = 0;
        const char *s = NULL;
        if (reset && tputLookup(e, resetNames[i], &n, &s) == 's' && s) {
            tputEmit(s);
        } else if (tputLookup(e, initNames[i], &n, &s) == 's' && s) {
            tputEmit(s);
        }
    }
}

/* -x: clear leaves the scrollback alone. */
static bool tputKeepScrollback = false;

/* One capability, with its parameters. Returns tput's exit status. */
static int tputOne(const TputEntry *e, int argc, char **argv) {
    const char *name = argv[0];
    int num = 0;
    const char *str = NULL;

    if (strcmp(name, "init") == 0 || strcmp(name, "reset") == 0) {
        tputInitStrings(e, strcmp(name, "reset") == 0);
        return 0;
    }
    if (strcmp(name, "longname") == 0) {
        const char *bar = e->names ? strrchr(e->names, '|') : NULL;
        fputs(bar ? bar + 1 : (e->names ? e->names : ""), stdout);
        return 0;
    }
    char kind = tputLookup(e, name, &num, &str);
    if (kind == 0) {
        fprintf(stderr, "tput: unknown terminfo capability '%s'\n", name);
        return 4;
    }
    if (kind == 'b') {
        return num ? 0 : 1;
    }
    if (kind == 'n') {
        int cols = 0, lines = 0;
        if ((strcmp(name, "cols") == 0 || strcmp(name, "lines") == 0) &&
            tputWindowSize(&cols, &lines)) {
            num = strcmp(name, "cols") == 0 ? cols : lines;
        }
        printf("%d\n", num);
        return 0;
    }
    if (!str) {
        /* ncurses' clear is its clear program, which says 2 for a terminal
         * that cannot clear. */
        return strcmp(name, "clear") == 0 ? 2 : 1;
    }
    if (argc == 1 && strstr(str, "%p")) {
        /* A parameterised capability with nothing to put in it: the string
         * itself, unexpanded, as ncurses' tput prints it. */
        tputEmit(str);
        return 0;
    }
    TputValue params[9];
    int count = 0;
    for (int i = 1; i < argc && count < 9; i++, count++) {
        if (tputLooksNumeric(argv[i])) {
            params[count] = (TputValue){ false, strtol(argv[i], NULL, 10), NULL };
        } else {
            params[count] = (TputValue){ true, 0, argv[i] };
        }
    }
    char *out = tputTparm(str, params, count);
    if (out) {
        tputEmit(out);
        free(out);
    }
    /* And the scrollback too, through the E3 extension, as ncurses' clear
     * does -- unless -x. */
    if (strcmp(name, "clear") == 0 && !tputKeepScrollback) {
        const char *e3 = NULL;
        if (tputLookup(e, "E3", &num, &e3) == 's' && e3) {
            tputEmit(e3);
        }
    }
    return 0;
}

static void tputFree(TputEntry *e) {
    free(e->names);
    free(e->extNames);
    free(e->blob);
    memset(e, 0, sizeof(*e));
}

int smallclueTputCommand(int argc, char **argv) {
    const char *term = NULL;
    bool fromStdin = false;
    int i = 1;
    for (; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--") == 0) {
            i++;
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            break;
        }
        if (strcmp(arg, "-T") == 0 && i + 1 < argc) {
            term = argv[++i];
        } else if (strncmp(arg, "-T", 2) == 0 && arg[2]) {
            term = arg + 2;
        } else if (strcmp(arg, "-S") == 0) {
            fromStdin = true;
        } else if (strcmp(arg, "-x") == 0) {
            tputKeepScrollback = true;
        } else if (strcmp(arg, "-V") == 0) {
            printf("tput (smallclue)\n");
            return 0;
        } else {
            fprintf(stderr, "usage: tput [-T term] [-S] [-x] capname [parameters...]\n");
            return 2;
        }
    }
    if (!term) {
        term = getenv("TERM");
    }
    if (!term || !*term) {
        fprintf(stderr, "tput: No value for $TERM and no -T specified\n");
        return 2;
    }
    if (!fromStdin && i >= argc) {
        fprintf(stderr, "usage: tput [-T term] [-S] [-x] capname [parameters...]\n");
        return 2;
    }
    TputEntry entry;
    if (!tputLoad(term, &entry)) {
        fprintf(stderr, "tput: unknown terminal \"%s\"\n", term);
        return 3;
    }
    int status = 0;
    if (fromStdin) {
        char line[1024];
        while (fgets(line, sizeof(line), stdin)) {
            char *words[16];
            int n = 0;
            for (char *tok = strtok(line, " \t\r\n"); tok && n < 16; tok = strtok(NULL, " \t\r\n")) {
                words[n++] = tok;
            }
            if (n > 0) {
                int st = tputOne(&entry, n, words);
                if (st > status) {
                    status = st;
                }
            }
        }
    } else {
        status = tputOne(&entry, argc - i, argv + i);
    }
    fflush(stdout);
    tputFree(&entry);
    return status;
}

/* ------------------------------------------------------------------- reset */

int smallclueResetCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (isatty(STDIN_FILENO) || isatty(STDERR_FILENO)) {
        char *sttyArgv[] = { (char *)"stty", (char *)"sane", NULL };
        (void)smallclueSttyCommand(2, sttyArgv);
    }
    const char *term = getenv("TERM");
    TputEntry entry;
    if (term && *term && tputLoad(term, &entry)) {
        tputInitStrings(&entry, true);
        int num = 0;
        const char *s = NULL;
        if (tputLookup(&entry, "cnorm", &num, &s) == 's' && s) {
            tputEmit(s);
        }
        tputFree(&entry);
    } else {
        /* No description: what every ANSI terminal understands, RIS. */
        fputs("\033c", stdout);
    }
    fflush(stdout);
    return 0;
}
