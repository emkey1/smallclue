/*
 * xargs: build and run command lines from standard input, compatible with
 * GNU findutils 4.9.
 *
 * The xargs this replaced read all of its input before running anything (so
 * `tail -f log | xargs -n1 cmd` never ran), had no -L, -P, -d, -a, -E, -s,
 * -x, -p, -o, ran a command found among the applets inside its own process
 * (where it read xargs's own standard input, and an exit() ended xargs), and
 * exited 1 for every failure. This is GNU's reader (quotes, backslashes,
 * blank-terminated continuation lines for -L, the logical end-of-file
 * string), its batching by -n, -L and the -s size limit, -I replacement in
 * every argument but the command name, -P with that many children at once,
 * /dev/null as each command's standard input, and its exit statuses: 123 when
 * a command failed, 124 when one exited 255, 125 when one was killed, 126/127
 * when one could not be run.
 *
 * Runs as a function call inside embedding hosts: no global state.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "xargs_app.h"
#include "app_hooks.h"
#include "gnu_util.h"
#include "spawn.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define XARGS_EXIT_NONZERO 123
#define XARGS_EXIT_255 124
#define XARGS_EXIT_SIGNAL 125
#define XARGS_EXIT_CANNOT_RUN 126
#define XARGS_EXIT_NOT_FOUND 127
#define XARGS_DEFAULT_SIZE 131072
#define XARGS_MAX_SIZE 2091008

typedef struct {
    /* options */
    int delim;              /* -1: quoting reader; else -0/-d byte */
    const char *eofStr;
    const char *replace;
    size_t maxLines, maxArgs, maxChars, maxProcs;
    bool noRunIfEmpty, verbose, interactive, exitIfTooBig, openTty;
    const char *slotVar;
    /* input */
    int fd;
    bool keepStdin;
    char buf[65536];
    size_t pos, len;
    bool eof;
    size_t lineno;          /* -L: complete lines in the pending command */
    bool nulWarned;
    /* the command being built */
    char **argv;
    size_t argc, argcap, initialArgc;
    size_t chars, initialChars;
    char *item;
    size_t itemLen, itemCap;
    /* children */
    pid_t *procs;
    size_t nprocs;
    size_t executed;
    int status;             /* worst so far */
    bool fatal;             /* stop: a fatal status was reached */
} Xargs;

static int xargsGetc(Xargs *x) {
    if (x->pos == x->len) {
        if (x->eof) return EOF;
        for (;;) {
            ssize_t n = read(x->fd, x->buf, sizeof(x->buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                x->eof = true;
                return EOF;
            }
            x->pos = 0;
            x->len = (size_t)n;
            break;
        }
    }
    return (unsigned char)x->buf[x->pos++];
}

static bool xargsItemPut(Xargs *x, char c) {
    if (x->itemLen + 1 >= x->itemCap) {
        size_t cap = x->itemCap ? x->itemCap * 2 : 256;
        char *n = (char *)realloc(x->item, cap);
        if (!n) return false;
        x->item = n;
        x->itemCap = cap;
    }
    x->item[x->itemLen++] = c;
    x->item[x->itemLen] = '\0';
    return true;
}

/* --- Running commands. --- */

static void xargsReport(Xargs *x, int wstatus, const char *name) {
    if (WIFEXITED(wstatus)) {
        int code = WEXITSTATUS(wstatus);
        if (code == 255) {
            fprintf(stderr, "xargs: %s: exited with status 255; aborting\n", name);
            x->status = XARGS_EXIT_255;
            x->fatal = true;
        } else if (code != 0 && x->status == 0) {
            x->status = XARGS_EXIT_NONZERO;
        }
    } else if (WIFSIGNALED(wstatus)) {
        fprintf(stderr, "xargs: %s: terminated by signal %d\n", name, WTERMSIG(wstatus));
        x->status = XARGS_EXIT_SIGNAL;
        x->fatal = true;
    }
}

typedef struct {
    pid_t pid;
    char *name;
} XargsChild;

/* Waits for one child (any, or until fewer than `keep` remain). */
static void xargsWaitFor(Xargs *x, XargsChild *kids, size_t *nkids, size_t keep) {
    while (*nkids > keep) {
        int st;
        pid_t pid = waitpid(-1, &st, 0);
        if (pid < 0) {
            if (errno == EINTR) continue;
            /* Lost track (an embedding host reaped them): forget them. */
            for (size_t i = 0; i < *nkids; i++) free(kids[i].name);
            *nkids = 0;
            return;
        }
        for (size_t i = 0; i < *nkids; i++) {
            if (kids[i].pid != pid) continue;
            xargsReport(x, st, kids[i].name);
            free(kids[i].name);
            kids[i] = kids[--*nkids];
            break;
        }
    }
}

typedef struct {
    XargsChild *v;
    size_t n, cap;
} XargsKids;

static bool xargsPrompt(const char *cmdline) {
    fprintf(stderr, "%s ?...", cmdline);
    fflush(stderr);
    FILE *tty = fopen("/dev/tty", "r");
    if (!tty) {
        fprintf(stderr, "\nxargs: failed to open /dev/tty for reading: %s\n", strerror(errno));
        return false;
    }
    char line[256];
    bool yes = fgets(line, sizeof(line), tty) && (line[0] == 'y' || line[0] == 'Y');
    fclose(tty);
    return yes;
}

static void xargsExec(Xargs *x, XargsKids *kids) {
    if (x->fatal) return;
    x->argv[x->argc] = NULL;
    x->executed++;
    if (x->verbose || x->interactive) {
        size_t n = 0;
        for (size_t i = 0; i < x->argc; i++) n += strlen(x->argv[i]) + 1;
        char *line = (char *)malloc(n + 1);
        if (line) {
            char *p = line;
            for (size_t i = 0; i < x->argc; i++) p += sprintf(p, "%s%s", i ? " " : "", x->argv[i]);
            if (x->interactive) {
                bool yes = xargsPrompt(line);
                free(line);
                if (!yes) return;
            } else {
                fprintf(stderr, "%s\n", line);
                fflush(stderr);
                free(line);
            }
        }
    }
    if (x->maxProcs != 1)
        xargsWaitFor(x, kids->v, &kids->n, x->maxProcs ? x->maxProcs - 1 : SIZE_MAX);
    if (x->fatal) return;
    fflush(stdout);

    /* What GNU's child does between fork and exec: standard input from
     * /dev/null (or the terminal with -o) unless the arguments came from -a,
     * and the slot variable. Done around the spawn here, as the spawn takes
     * the caller's descriptors and environment. */
    int savedIn = -1;
    if (!x->keepStdin || x->openTty) {
        int in = open(x->openTty ? "/dev/tty" : "/dev/null", O_RDONLY);
        if (in < 0 && x->openTty) {
            fprintf(stderr, "xargs: failed to open /dev/tty for reading: %s\n", strerror(errno));
            x->status = 1;
            x->fatal = true;
            return;
        }
        if (in >= 0) {
            savedIn = dup(0);
            dup2(in, 0);
            close(in);
        }
    }
    char *oldSlot = NULL;
    size_t slot = kids->n;
    if (x->slotVar) {
        const char *old = getenv(x->slotVar);
        oldSlot = old ? strdup(old) : NULL;
        char num[32];
        snprintf(num, sizeof(num), "%zu", slot);
        setenv(x->slotVar, num, 1);
    }

    int ranStatus = 0;
    bool ranInProcess = smallclueAppRunInProcess((int)x->argc, x->argv, &ranStatus);
    pid_t pid = -1;
    int spawnErr = 0;
    if (!ranInProcess) {
        pid = smallclueSpawnSimple(x->argv[0], x->argv, 1);
        spawnErr = errno;
    }

    if (savedIn >= 0) {
        dup2(savedIn, 0);
        close(savedIn);
    }
    if (x->slotVar) {
        if (oldSlot) setenv(x->slotVar, oldSlot, 1);
        else unsetenv(x->slotVar);
        free(oldSlot);
    }

    if (ranInProcess) {
        xargsReport(x, (ranStatus & 0xff) << 8, x->argv[0]);
        return;
    }
    if (pid < 0) {
        fprintf(stderr, "xargs: %s: %s\n", x->argv[0], strerror(spawnErr));
        x->status = spawnErr == ENOENT ? XARGS_EXIT_NOT_FOUND : XARGS_EXIT_CANNOT_RUN;
        x->fatal = true;
        return;
    }
    if (kids->n == kids->cap) {
        size_t cap = kids->cap ? kids->cap * 2 : 8;
        XargsChild *v = (XargsChild *)realloc(kids->v, cap * sizeof(XargsChild));
        if (!v) { x->fatal = true; x->status = 1; return; }
        kids->v = v;
        kids->cap = cap;
    }
    kids->v[kids->n].pid = pid;
    kids->v[kids->n].name = strdup(x->argv[0]);
    kids->n++;
    if (x->maxProcs == 1) xargsWaitFor(x, kids->v, &kids->n, 0);
}

/* Drops the arguments read so far, keeping the initial ones. */
static void xargsClear(Xargs *x) {
    for (size_t i = x->initialArgc; i < x->argc; i++) free(x->argv[i]);
    x->argc = x->initialArgc;
    x->chars = x->initialChars;
    x->lineno = 0;
}

static void xargsDoExec(Xargs *x, XargsKids *kids) {
    xargsExec(x, kids);
    xargsClear(x);
}

static bool xargsAppend(Xargs *x, char *owned) {
    if (x->argc + 2 > x->argcap) {
        size_t cap = x->argcap ? x->argcap * 2 : 64;
        char **v = (char **)realloc(x->argv, cap * sizeof(char *));
        if (!v) { free(owned); return false; }
        x->argv = v;
        x->argcap = cap;
    }
    x->argv[x->argc++] = owned;
    return true;
}

/* GNU's bc_push_arg: runs the pending command first when this argument
 * would not fit, then after it when -n is reached. */
static void xargsPush(Xargs *x, XargsKids *kids, const char *arg, size_t len) {
    size_t need = len + 1;
    if (x->chars + need > x->maxChars) {
        if (x->argc == x->initialArgc) {
            fputs("xargs: argument line too long\n", stderr);
            x->status = 1;
            x->fatal = true;
            return;
        }
        if (x->exitIfTooBig && (x->maxLines || x->maxArgs)) {
            fputs("xargs: argument list too long\n", stderr);
            x->status = 1;
            x->fatal = true;
            return;
        }
        xargsDoExec(x, kids);
        if (x->fatal) return;
    }
    char *copy = (char *)malloc(need);
    if (!copy) { x->fatal = true; x->status = 1; return; }
    memcpy(copy, arg, len);
    copy[len] = '\0';
    if (!xargsAppend(x, copy)) { x->fatal = true; x->status = 1; return; }
    x->chars += need;
    if (x->maxArgs && x->argc - x->initialArgc >= x->maxArgs) xargsDoExec(x, kids);
}

static bool xargsIsEof(const Xargs *x) {
    return x->eofStr && !strcmp(x->item, x->eofStr);
}

/* GNU runs what it has before dying of an input error (exec_if_possible). */
static void xargsInputError(Xargs *x, XargsKids *kids) {
    if (x->argc > x->initialArgc && !x->replace) xargsDoExec(x, kids);
    x->status = 1;
    x->fatal = true;
}

static void xargsUnmatched(Xargs *x, XargsKids *kids, int quote) {
    xargsInputError(x, kids);
    fprintf(stderr, "xargs: unmatched %s quote; by default quotes are special to xargs unless you use the -0 option\n",
            quote == '"' ? "double" : "single");
}

/* GNU's read_line: one input line's arguments (or, with -I, the line as one
 * item). Returns false at end of input. */
static bool xargsReadLine(Xargs *x, XargsKids *kids) {
    enum { NORM, SPACE, QUOTE, BACKSLASH } state = SPACE;
    int c = EOF, prev, quote = 0;
    bool first = true;
    x->itemLen = 0;
    if (!xargsItemPut(x, 0)) return false;
    x->itemLen = 0;
    if (x->eof && x->pos == x->len) return false;
    for (;;) {
        prev = c;
        c = xargsGetc(x);
        if (c == EOF) {
            if (state == QUOTE) {
                xargsUnmatched(x, kids, quote);
                return false;
            }
            if (x->itemLen == 0) return false;
            if (first && xargsIsEof(x)) return false;
            if (!x->replace) xargsPush(x, kids, x->item, x->itemLen);
            return true;
        }
        switch (state) {
        case SPACE:
            if (isspace(c)) continue;
            state = NORM;
            /* fall through */
        case NORM:
            if (c == '\n') {
                if (!(prev == ' ' || prev == '\t')) x->lineno++;
                if (x->itemLen == 0) {
                    state = SPACE;
                    continue;
                }
                if (xargsIsEof(x)) {
                    x->eof = true;
                    x->pos = x->len;
                    return !first;
                }
                if (!x->replace) xargsPush(x, kids, x->item, x->itemLen);
                return true;
            }
            if (!x->replace && (c == ' ' || c == '\t')) {
                if (xargsIsEof(x)) {
                    x->eof = true;
                    x->pos = x->len;
                    return !first;
                }
                xargsPush(x, kids, x->item, x->itemLen);
                if (x->fatal) return false;
                x->itemLen = 0;
                x->item[0] = '\0';
                state = SPACE;
                first = false;
                continue;
            }
            if (c == '\\') { state = BACKSLASH; continue; }
            if (c == '\'' || c == '"') { state = QUOTE; quote = c; continue; }
            break;
        case QUOTE:
            if (c == '\n') {
                xargsUnmatched(x, kids, quote);
                return false;
            }
            if (c == quote) { state = NORM; continue; }
            break;
        case BACKSLASH:
            state = NORM;
            break;
        }
        if (c == 0 && !x->nulWarned) {
            fputs("xargs: WARNING: a NUL character occurred in the input.  It cannot be passed through in the "
                  "argument list.  Did you mean to use the --null option?\n", stderr);
            x->nulWarned = true;
        }
        if (x->itemLen + 1 > x->maxChars) {
            xargsInputError(x, kids);
            fputs("xargs: argument line too long\n", stderr);
            return false;
        }
        if (!xargsItemPut(x, (char)c)) return false;
    }
}

/* GNU's read_string, for -0 and -d: items end at the delimiter only. */
static bool xargsReadString(Xargs *x, XargsKids *kids) {
    x->itemLen = 0;
    if (!xargsItemPut(x, 0)) return false;
    x->itemLen = 0;
    for (;;) {
        int c = xargsGetc(x);
        if (c == EOF) {
            if (x->itemLen == 0) return false;
            break;
        }
        if (c == x->delim) {
            x->lineno++;
            break;
        }
        if (!xargsItemPut(x, (char)c)) return false;
    }
    if (xargsIsEof(x)) {
        x->eof = true;
        x->pos = x->len;
        return false;
    }
    if (!x->replace) xargsPush(x, kids, x->item, x->itemLen);
    return true;
}

static char *xargsReplaceAll(const char *s, const char *pat, const char *val) {
    size_t pl = strlen(pat), vl = strlen(val), n = 0;
    if (pl == 0) return strdup(s);
    for (const char *p = s; (p = strstr(p, pat)); p += pl) n++;
    char *out = (char *)malloc(strlen(s) + n * vl + 1), *o = out;
    if (!out) return NULL;
    for (const char *p = s, *m; ; p = m + pl) {
        m = strstr(p, pat);
        size_t k = m ? (size_t)(m - p) : strlen(p);
        memcpy(o, p, k);
        o += k;
        if (!m) break;
        memcpy(o, val, vl);
        o += vl;
    }
    *o = '\0';
    return out;
}

/* --- Options. --- */

static int xargsTry(void) {
    fputs("Try 'xargs --help' for more information.\n", stderr);
    return 1;
}

static void xargsUsage(void) {
    fputs("Usage: xargs [OPTION]... COMMAND [INITIAL-ARGS]...\n"
          "Run COMMAND with arguments INITIAL-ARGS and more arguments read from input.\n"
          "\n"
          "  -0, --null                   items are separated by a null, not whitespace;\n"
          "                                 disables quote and backslash processing and\n"
          "                                 logical EOF processing\n"
          "  -a, --arg-file=FILE          read arguments from FILE, not standard input\n"
          "  -d, --delimiter=CHARACTER    items in input stream are separated by CHARACTER,\n"
          "                                 not by whitespace; disables quote and backslash\n"
          "                                 processing and logical EOF processing\n"
          "  -E END                       set logical EOF string; if END occurs as a line\n"
          "                                 of input, the rest of the input is ignored\n"
          "  -e, --eof[=END]              equivalent to -E END if END is specified;\n"
          "                                 otherwise, there is no end-of-file string\n"
          "  -I R                         same as --replace=R\n"
          "  -i, --replace[=R]            replace R in INITIAL-ARGS with names read\n"
          "                                 from standard input, split at newlines;\n"
          "                                 if R is unspecified, assume {}\n"
          "  -L, --max-lines=MAX-LINES    use at most MAX-LINES non-blank input lines per\n"
          "                                 command line\n"
          "  -l[MAX-LINES]                similar to -L but defaults to at most one non-\n"
          "                                 blank input line if MAX-LINES is not specified\n"
          "  -n, --max-args=MAX-ARGS      use at most MAX-ARGS arguments per command line\n"
          "  -o, --open-tty               Reopen stdin as /dev/tty in the child process\n"
          "                                 before executing the command\n"
          "  -P, --max-procs=MAX-PROCS    run at most MAX-PROCS processes at a time\n"
          "  -p, --interactive            prompt before running commands\n"
          "      --process-slot-var=VAR   set environment variable VAR in child processes\n"
          "  -r, --no-run-if-empty        if there are no arguments, then do not run COMMAND;\n"
          "                                 if this option is not given, COMMAND will be\n"
          "                                 run at least once\n"
          "  -s, --max-chars=MAX-CHARS    limit length of command line to MAX-CHARS\n"
          "      --show-limits            show limits on command-line length\n"
          "  -t, --verbose                print commands before executing them\n"
          "  -x, --exit                   exit if the size (see -s) is exceeded\n"
          "      --help                   display this help and exit\n"
          "      --version                output version information and exit\n",
          stdout);
}

/* -d's argument: one byte, or a C escape. -1 after a message. */
static int xargsDelim(const char *s) {
    if (s[0] && !s[1]) return (unsigned char)s[0];
    if (s[0] == '\\') {
        static const char esc[] = "a\ab\bf\fn\nr\rt\tv\v\\\\";
        for (const char *e = esc; *e; e += 2)
            if (s[1] == e[0] && !s[2]) return (unsigned char)e[1];
        char *end;
        long v = -1;
        if (s[1] == 'x' && s[2]) v = strtol(s + 2, &end, 16);
        else if (s[1] >= '0' && s[1] <= '7') v = strtol(s + 1, &end, 8);
        if (v >= 0 && v <= 255 && *end == '\0') return (int)v;
    }
    fprintf(stderr, "xargs: Invalid input delimiter specification %s: the delimiter must be either a single "
                    "character or an escape sequence starting with \\.\n", s);
    return -1;
}

static bool xargsCount(const char *opt, const char *val, size_t min, size_t *out) {
    char *end;
    errno = 0;
    long long v = strtoll(val, &end, 10);
    if (*val == '\0' || *end != '\0' || errno) {
        fprintf(stderr, "xargs: invalid number \"%s\" for -%s option\n", val, opt);
        xargsTry();
        return false;
    }
    if (v < (long long)min) {
        fprintf(stderr, "xargs: value %s for -%s option should be >= %zu\n", val, opt, min);
        xargsTry();
        return false;
    }
    *out = (size_t)v;
    return true;
}

typedef struct {
    const char *name;
    char shortEq;
    int arg;        /* 0 none, 1 required, 2 optional */
} XargsLong;

static const XargsLong xargsLongs[] = {
    {"arg-file", 'a', 1}, {"delimiter", 'd', 1}, {"eof", 'e', 2}, {"exit", 'x', 0},
    {"help", 'h', 0}, {"interactive", 'p', 0}, {"max-args", 'n', 1}, {"max-chars", 's', 1},
    {"max-lines", 'l', 2}, {"max-procs", 'P', 1}, {"no-run-if-empty", 'r', 0}, {"null", '0', 0},
    {"open-tty", 'o', 0}, {"process-slot-var", 'S', 1}, {"replace", 'i', 2}, {"show-limits", 'Z', 0},
    {"verbose", 't', 0}, {"version", 'v', 0},
};

/* One option; 0 to go on, 1 to exit with x->status, 2 to exit 0 (--help). */
static int xargsApply(Xargs *x, char c, const char *val, const char **argFile, bool *showLimits) {
    switch (c) {
    case '0': x->delim = '\0'; break;
    case 'a': *argFile = val; break;
    case 'd': {
        int d = xargsDelim(val);
        if (d < 0) { x->status = 1; return 1; }
        x->delim = d;
        break;
    }
    case 'E': x->eofStr = val && *val ? val : NULL; break;
    case 'e': x->eofStr = NULL; break;
    /* GNU's precedence: -I drops an earlier -n or -L, -L or -l an earlier -n
     * or -I, and -n an earlier -L (an -I stays, and -n is then unused). */
    case 'I': case 'i':
        if (x->maxArgs) {
            fputs("xargs: warning: options --max-args and --replace/-I/-i are mutually exclusive, "
                  "ignoring previous --max-args value\n", stderr);
            x->maxArgs = 0;
        }
        if (x->maxLines) {
            fputs("xargs: warning: options --max-lines and --replace/-I/-i are mutually exclusive, "
                  "ignoring previous --max-lines value\n", stderr);
            x->maxLines = 0;
        }
        x->replace = c == 'I' ? val : "{}";
        x->exitIfTooBig = true;
        break;
    case 'L': case 'l': {
        const char *name = c == 'L' ? "-L" : "--max-lines/-l";
        if (c == 'L' && !xargsCount("L", val, 1, &x->maxLines)) { x->status = 1; return 1; }
        if (c == 'l') x->maxLines = 1;
        if (x->maxArgs) {
            fprintf(stderr, "xargs: warning: options --max-args and %s are mutually exclusive, "
                            "ignoring previous --max-args value\n", name);
            x->maxArgs = 0;
        }
        if (x->replace) {
            fprintf(stderr, "xargs: warning: options --replace and %s are mutually exclusive, "
                            "ignoring previous --replace value\n", name);
            x->replace = NULL;
        }
        break;
    }
    case 'n':
        if (!xargsCount("n", val, 1, &x->maxArgs)) { x->status = 1; return 1; }
        if (x->maxLines) {
            fputs("xargs: warning: options --max-lines and --max-args/-n are mutually exclusive, "
                  "ignoring previous --max-lines value\n", stderr);
            x->maxLines = 0;
        }
        break;
    case 'o': x->openTty = true; break;
    case 'P':
        if (!xargsCount("P", val, 0, &x->maxProcs)) { x->status = 1; return 1; }
        break;
    case 'p': x->interactive = true; x->verbose = true; break;
    case 'r': x->noRunIfEmpty = true; break;
    case 's':
        /* Out of range is reported and then clamped, not fatal. */
        if (!xargsCount("s", val, 0, &x->maxChars)) { x->status = 1; return 1; }
        if (x->maxChars < 1) {
            fprintf(stderr, "xargs: value %s for -s option should be >= 1\n", val);
            x->maxChars = 1;
        } else if (x->maxChars > XARGS_MAX_SIZE) {
            fprintf(stderr, "xargs: value %s for -s option should be <= %d\n", val, XARGS_MAX_SIZE);
            x->maxChars = XARGS_MAX_SIZE;
        }
        break;
    case 'S': x->slotVar = val; break;
    case 't': x->verbose = true; break;
    case 'x': x->exitIfTooBig = true; break;
    case 'Z': *showLimits = true; break;
    case 'h': xargsUsage(); return 2;
    case 'v': puts("xargs (SmallCLUE) 4.9.0"); return 2;
    default: break;
    }
    return 0;
}

int smallclueXargsCommand(int argc, char **argv) {
    Xargs *x = (Xargs *)calloc(1, sizeof(Xargs));
    XargsKids kids = {NULL, 0, 0};
    const char *argFile = NULL;
    bool showLimits = false;
    int status = 0;
    if (!x) return 1;
    x->delim = -1;
    x->maxChars = XARGS_DEFAULT_SIZE;
    x->maxProcs = 1;
    x->fd = 0;

    /* Options end at the first operand: the rest is the command. */
    int i = 1;
    for (; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0') break;
        if (!strcmp(arg, "--")) { i++; break; }
        int r = 0;
        if (arg[1] == '-') {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            size_t len = eq ? (size_t)(eq - opt) : strlen(opt);
            const XargsLong *m = NULL;
            int matches = 0;
            for (size_t k = 0; k < sizeof(xargsLongs) / sizeof(xargsLongs[0]); k++) {
                if (strncmp(xargsLongs[k].name, opt, len)) continue;
                if (strlen(xargsLongs[k].name) == len) { m = &xargsLongs[k]; matches = 1; break; }
                m = &xargsLongs[k];
                matches++;
            }
            if (matches != 1) {
                fprintf(stderr, matches ? "xargs: option '%s' is ambiguous\n" : "xargs: unrecognized option '%s'\n", arg);
                status = xargsTry();
                goto done;
            }
            char c = m->shortEq;
            const char *val = NULL;
            if (eq) {
                if (m->arg == 0) {
                    fprintf(stderr, "xargs: option '--%s' doesn't allow an argument\n", m->name);
                    status = xargsTry();
                    goto done;
                }
                val = eq + 1;
                /* --max-lines=N, --replace=R, --eof=E: the valued forms. */
                if (c == 'l') c = 'L';
                else if (c == 'i') c = 'I';
                else if (c == 'e') c = 'E';
            } else if (m->arg == 1) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "xargs: option '--%s' requires an argument\n", m->name);
                    status = xargsTry();
                    goto done;
                }
                val = argv[++i];
            }
            r = xargsApply(x, c, val, &argFile, &showLimits);
        } else {
            for (const char *p = arg + 1; *p && r == 0; p++) {
                char c = *p;
                const char *val = NULL;
                if (strchr("aEIdLnPs", c)) {
                    if (p[1]) val = p + 1;
                    else if (i + 1 < argc) val = argv[++i];
                    else {
                        fprintf(stderr, "xargs: option requires an argument -- '%c'\n", c);
                        status = xargsTry();
                        goto done;
                    }
                } else if (strchr("eil", c)) {
                    /* Optional values attach: -l5, -i{}, -eEND. */
                    if (p[1]) {
                        val = p + 1;
                        c = c == 'e' ? 'E' : c == 'i' ? 'I' : 'L';
                    }
                } else if (!strchr("0oprtx", c)) {
                    fprintf(stderr, "xargs: invalid option -- '%c'\n", c);
                    status = xargsTry();
                    goto done;
                }
                r = xargsApply(x, c, val, &argFile, &showLimits);
                if (val) break;
            }
        }
        if (r == 1) { status = x->status; goto done; }
        if (r == 2) goto done;
    }
    if (x->slotVar && strchr(x->slotVar, '=')) {
        fprintf(stderr, "xargs: option --process-slot-var may not be set to a value which includes '='\n");
        status = 1;
        goto done;
    }

    if (showLimits) {
        size_t env = 0;
        extern char **environ;
        for (char **e = environ; e && *e; e++) env += strlen(*e) + 1;
        fprintf(stderr, "Your environment variables take up %zu bytes\n"
                        "POSIX upper limit on argument length (this system): %d\n"
                        "POSIX smallest allowable upper limit on argument length (all systems): 4096\n"
                        "Maximum length of command we could actually use: %zu\n"
                        "Size of command buffer we are actually using: %zu\n"
                        "Maximum parallelism (--max-procs must be no greater): %d\n",
                env, XARGS_MAX_SIZE + 2048, (size_t)XARGS_MAX_SIZE + 2048 - env, x->maxChars, INT_MAX);
        if (isatty(0))
            fputs("\nExecution of xargs will continue now, and it will try to read its input and run commands; "
                  "if this is not what you wanted to happen, please type the end-of-file keystroke.\n", stderr);
    }

    if (argFile) {
        char q[4096];
        x->keepStdin = true;
        if (!strcmp(argFile, "-")) {
            x->fd = 0;
            x->keepStdin = false;
        } else {
            FILE *fp = smallclueAppOpenRead(argFile);
            if (!fp) {
                fprintf(stderr, "xargs: Cannot open input file %s: %s\n", gnuQuoteLocale(argFile, q, sizeof(q)), strerror(errno));
                status = 1;
                goto done;
            }
            x->fd = dup(fileno(fp));
            fclose(fp);
        }
    }

    /* The initial arguments: the command (echo by default) and its own. */
    static char *const echoCmd[] = {(char *)"echo", NULL};
    char *const *cmd = i < argc ? argv + i : echoCmd;
    size_t ncmd = i < argc ? (size_t)(argc - i) : 1;
    for (size_t k = 0; k < ncmd; k++) {
        size_t need = strlen(cmd[k]) + 1;
        if (x->chars + need > x->maxChars) {
            fputs("xargs: cannot fit single argument within argument list size limit\n", stderr);
            status = 1;
            goto done;
        }
        char *copy = strdup(cmd[k]);
        if (!copy || !xargsAppend(x, copy)) { status = 1; goto done; }
        x->chars += need;
    }
    x->initialArgc = x->argc;
    x->initialChars = x->chars;

    if (!x->replace) {
        while (!x->fatal && (x->delim >= 0 ? xargsReadString(x, &kids) : xargsReadLine(x, &kids))) {
            if (x->maxLines && x->lineno >= x->maxLines) xargsDoExec(x, &kids);
        }
        if (!x->fatal && (x->argc != x->initialArgc || (!x->noRunIfEmpty && x->executed == 0)))
            xargsDoExec(x, &kids);
    } else {
        while (!x->fatal && (x->delim >= 0 ? xargsReadString(x, &kids) : xargsReadLine(x, &kids))) {
            /* Every argument but the command name gets the replacement. */
            char *line = strdup(x->item);
            if (!line) break;
            xargsClear(x);
            for (size_t k = 1; k < x->initialArgc; k++) {
                free(x->argv[k]);
                x->argv[k] = xargsReplaceAll(cmd[k], x->replace, line);
            }
            size_t total = 0;
            for (size_t k = 0; k < x->initialArgc; k++) total += strlen(x->argv[k]) + 1;
            free(line);
            if (total > x->maxChars) {
                fputs("xargs: argument line too long\n", stderr);
                x->status = 1;
                break;
            }
            xargsExec(x, &kids);
        }
    }
    xargsWaitFor(x, kids.v, &kids.n, 0);
    status = x->status;

done:
    if (x->fd > 0) close(x->fd);
    for (size_t k = 0; k < x->argc; k++) free(x->argv[k]);
    free(x->argv);
    free(x->item);
    for (size_t k = 0; k < kids.n; k++) free(kids.v[k].name);
    free(kids.v);
    free(x);
    if (fflush(stdout) != 0 && status == 0) status = 1;
    return status;
}
