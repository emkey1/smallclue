/*
 * env: GNU coreutils 9 compatible. -i (and a lone "-"), -u, -0, -C, -S
 * with GNU's splitting (quotes, \_ \c \t..., ${VAR}, # comments; options
 * read again from the split words), -v's debug trace, --default-signal,
 * --ignore-signal, --block-signal and --list-signal-handling, NAME=VALUE
 * through putenv (so "=x" works as it does there), and the 125/126/127
 * exit statuses. Signals are named and numbered as Linux has them.
 */

#include "env_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { ENV_CANCELED = 125, ENV_CANNOT_INVOKE = 126, ENV_ENOENT = 127 };
enum { SIG_UNCHANGED, SIG_TO_DEFAULT, SIG_TO_DEFAULT_NOERR, SIG_TO_IGNORE, SIG_TO_IGNORE_NOERR };

/* Linux's numbers, the host's constants. */
static const struct { const char *name; int num; int host;   /* not "linux": a gcc predefined macro */ } envSignals[] = {
    {"HUP", 1, SIGHUP},     {"INT", 2, SIGINT},     {"QUIT", 3, SIGQUIT},   {"ILL", 4, SIGILL},
    {"TRAP", 5, SIGTRAP},   {"ABRT", 6, SIGABRT},   {"BUS", 7, SIGBUS},     {"FPE", 8, SIGFPE},
    {"KILL", 9, SIGKILL},   {"USR1", 10, SIGUSR1},  {"SEGV", 11, SIGSEGV},  {"USR2", 12, SIGUSR2},
    {"PIPE", 13, SIGPIPE},  {"ALRM", 14, SIGALRM},  {"TERM", 15, SIGTERM},
#ifdef SIGSTKFLT
    {"STKFLT", 16, SIGSTKFLT},
#endif
    {"CHLD", 17, SIGCHLD},  {"CONT", 18, SIGCONT},  {"STOP", 19, SIGSTOP},  {"TSTP", 20, SIGTSTP},
    {"TTIN", 21, SIGTTIN},  {"TTOU", 22, SIGTTOU},  {"URG", 23, SIGURG},    {"XCPU", 24, SIGXCPU},
    {"XFSZ", 25, SIGXFSZ},  {"VTALRM", 26, SIGVTALRM}, {"PROF", 27, SIGPROF}, {"WINCH", 28, SIGWINCH},
    {"IO", 29, SIGIO},
#ifdef SIGPWR
    {"PWR", 30, SIGPWR},
#endif
    {"SYS", 31, SIGSYS},
};
#define ENV_NSIG ((int)(sizeof(envSignals) / sizeof(envSignals[0])))

/* GNU sets its locale once, at start; env -i must not change the style.
 * Per thread: in-process hosts run applets on several. */
static __thread bool envUtf8;
static const char *envQuote(const char *s, char *buf, size_t n) {
    return gnuQuoteLocaleAs(envUtf8, s, buf, n);
}

typedef struct {
    bool debug;
    int action[ENV_NSIG];
    bool block[ENV_NSIG];
    bool maskChanged;
} Env;

static void envDev(const Env *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void envDev(const Env *e, const char *fmt, ...) {
    if (!e->debug) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* operand2sig: an index into envSignals, or -1 after GNU's message. */
static int envSignal(const char *s) {
    char q[256];
    int idx = -1;
    if (isdigit((unsigned char)*s)) {
        char *end;
        long n = strtol(s, &end, 10);
        if (!*end)
            for (int i = 0; i < ENV_NSIG; i++)
                if (envSignals[i].num == n) idx = i;
    } else {
        char up[32];
        size_t n = 0;
        for (const char *p = s; *p && n < sizeof(up) - 1; p++) up[n++] = (char)toupper((unsigned char)*p);
        up[n] = '\0';
        const char *name = !strncmp(up, "SIG", 3) ? up + 3 : up;
        if (!strcmp(name, "POLL")) name = "IO";
        if (!strcmp(name, "IOT")) name = "ABRT";
        for (int i = 0; i < ENV_NSIG; i++)
            if (!strcmp(envSignals[i].name, name)) idx = i;
    }
    if (idx < 0) fprintf(stderr, "env: %s: invalid signal\n", envQuote(s, q, sizeof(q)));
    return idx;
}

static bool envSignalAction(Env *e, const char *arg, bool toDefault) {
    if (!arg) {
        for (int i = 0; i < ENV_NSIG; i++)
            if (envSignals[i].host != SIGKILL && envSignals[i].host != SIGSTOP)
                e->action[i] = toDefault ? SIG_TO_DEFAULT_NOERR : SIG_TO_IGNORE_NOERR;
        return true;
    }
    char *copy = strdup(arg);
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        int i = envSignal(tok);
        if (i < 0) {
            free(copy);
            return false;
        }
        e->action[i] = toDefault ? SIG_TO_DEFAULT : SIG_TO_IGNORE;
    }
    free(copy);
    return true;
}

static bool envBlock(Env *e, const char *arg) {
    e->maskChanged = true;
    if (!arg) {
        for (int i = 0; i < ENV_NSIG; i++) e->block[i] = true;
        return true;
    }
    char *copy = strdup(arg);
    for (char *tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
        int i = envSignal(tok);
        if (i < 0) {
            free(copy);
            return false;
        }
        e->block[i] = true;
    }
    free(copy);
    return true;
}

/* Signal changes, then the listing; false (after the message) on failure. */
static bool envApplySignals(Env *e, bool list) {
    for (int i = 0; i < ENV_NSIG; i++) {
        int a = e->action[i];
        if (a == SIG_UNCHANGED) continue;
        bool noerr = a == SIG_TO_DEFAULT_NOERR || a == SIG_TO_IGNORE_NOERR;
        bool toDefault = a == SIG_TO_DEFAULT || a == SIG_TO_DEFAULT_NOERR;
        struct sigaction act;
        int err = sigaction(envSignals[i].host, NULL, &act);
        if (err && !noerr) {
            fprintf(stderr, "env: failed to get signal action for signal %d: %s\n", envSignals[i].num,
                    strerror(errno));
            return false;
        }
        if (!err) {
            act.sa_handler = toDefault ? SIG_DFL : SIG_IGN;
            err = sigaction(envSignals[i].host, &act, NULL);
            if (err && !noerr) {
                fprintf(stderr, "env: failed to set signal action for signal %d: %s\n", envSignals[i].num,
                        strerror(errno));
                return false;
            }
        }
        envDev(e, "Reset signal %s (%d) to %s%s\n", envSignals[i].name, envSignals[i].num,
               toDefault ? "DEFAULT" : "IGNORE", err ? " (failure ignored)" : "");
    }
    if (e->maskChanged) {
        sigset_t set;
        sigemptyset(&set);
        sigprocmask(SIG_BLOCK, NULL, &set);
        for (int i = 0; i < ENV_NSIG; i++) {
            if (!e->block[i]) continue;
            sigaddset(&set, envSignals[i].host);
            envDev(e, "signal %s (%d) mask set to %s\n", envSignals[i].name, envSignals[i].num, "BLOCK");
        }
        if (sigprocmask(SIG_SETMASK, &set, NULL) != 0) {
            fprintf(stderr, "env: failed to set signal process mask: %s\n", strerror(errno));
            return false;
        }
    }
    if (list) {
        sigset_t set;
        sigemptyset(&set);
        sigprocmask(SIG_BLOCK, NULL, &set);
        for (int i = 0; i < ENV_NSIG; i++) {
            struct sigaction act;
            if (sigaction(envSignals[i].host, NULL, &act) != 0) continue;
            const char *ignored = act.sa_handler == SIG_IGN ? "IGNORE" : "";
            const char *blocked = sigismember(&set, envSignals[i].host) ? "BLOCK" : "";
            if (!*ignored && !*blocked) continue;
            fprintf(stderr, "%-10s (%2d): %s%s%s\n", envSignals[i].name, envSignals[i].num, blocked,
                    *ignored && *blocked ? "," : "", ignored);
        }
    }
    return true;
}

typedef struct {
    char **v;
    int n, cap;
    char *cur;
    size_t len, curCap;
    bool sep;
} EnvSplit;

static void envSplitPush(EnvSplit *s) {
    if (s->n + 1 >= s->cap) {
        s->cap = s->cap ? s->cap * 2 : 8;
        s->v = (char **)realloc(s->v, (size_t)s->cap * sizeof(char *));
    }
    s->cur = (char *)calloc(1, 16);
    s->curCap = 16;
    s->len = 0;
    s->v[s->n++] = s->cur;
    s->v[s->n] = NULL;
}

static void envSplitByte(EnvSplit *s, char c) {
    if (s->len + 2 > s->curCap) {
        s->curCap *= 2;
        s->cur = (char *)realloc(s->cur, s->curCap);
        s->v[s->n - 1] = s->cur;
    }
    s->cur[s->len++] = c;
    s->cur[s->len] = '\0';
}

static void envSplitStart(EnvSplit *s) {
    if (s->sep) {
        envSplitPush(s);
        s->sep = false;
    }
}

/* GNU's build_argv; NULL (after the message) on a bad string. */
static char **envBuildArgv(const Env *e, const char *str, int *argc) {
    EnvSplit s = {0};
    s.sep = true;
    bool dq = false, sq = false;
    char q[512];
    while (*str) {
        char c = *str;
        switch (*str) {
        case '\'':
            if (dq) break;
            sq = !sq;
            envSplitStart(&s);
            str++;
            continue;
        case '"':
            if (sq) break;
            dq = !dq;
            envSplitStart(&s);
            str++;
            continue;
        case ' ': case '\t': case '\n': case '\v': case '\f': case '\r':
            if (sq || dq) break;
            s.sep = true;
            str += strspn(str, " \t\n\v\f\r");
            continue;
        case '#':
            if (!s.sep) break;
            goto eos;
        case '\\':
            if (sq && str[1] != '\\' && str[1] != '\'') break;
            c = *++str;
            switch (c) {
            case '"': case '#': case '$': case '\'': case '\\': break;
            case '_':
                if (!dq) {
                    str++;
                    s.sep = true;
                    continue;
                }
                c = ' ';
                break;
            case 'c':
                if (dq) {
                    fputs("env: '\\c' must not appear in double-quoted -S string\n", stderr);
                    goto bad;
                }
                goto eos;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'v': c = '\v'; break;
            case '\0':
                fputs("env: invalid backslash at end of string in -S\n", stderr);
                goto bad;
            default:
                fprintf(stderr, "env: invalid sequence '\\%c' in -S\n", c);
                goto bad;
            }
            break;
        case '$': {
            if (sq) break;
            const char *p = str + 1;
            bool okName = *p == '{' && (isalpha((unsigned char)p[1]) || p[1] == '_');
            const char *nm = p + 1, *q2 = nm;
            if (okName) {
                while (isalnum((unsigned char)*q2) || *q2 == '_') q2++;
                okName = *q2 == '}';
            }
            if (!okName) {
                fprintf(stderr, "env: only ${VARNAME} expansion is supported, error at: %s\n", str);
                goto bad;
            }
            char name[256];
            snprintf(name, sizeof(name), "%.*s", (int)(q2 - nm), nm);
            const char *v = getenv(name);
            if (v) {
                envSplitStart(&s);
                envDev(e, "expanding ${%s} into %s\n", name, envQuote(v, q, sizeof(q)));
                for (; *v; v++) envSplitByte(&s, *v);
            } else {
                envDev(e, "replacing ${%s} with null string\n", name);
            }
            str = q2 + 1;
            continue;
        }
        }
        envSplitStart(&s);
        envSplitByte(&s, c);
        str++;
    }
    if (dq || sq) {
        fputs("env: no terminating quote in -S string\n", stderr);
        goto bad;
    }
eos:
    *argc = s.n;
    if (!s.v) {
        s.v = (char **)calloc(1, sizeof(char *));
    }
    return s.v;
bad:
    for (int i = 0; i < s.n; i++) free(s.v[i]);
    free(s.v);
    return NULL;
}

static const GnuLongOpt envLongs[] = {
    {"ignore-environment", GNU_NO_ARG, 'i'}, {"null", GNU_NO_ARG, '0'},
    {"unset", GNU_REQ_ARG, 'u'},             {"chdir", GNU_REQ_ARG, 'C'},
    {"default-signal", GNU_OPT_ARG, 1},      {"ignore-signal", GNU_OPT_ARG, 2},
    {"block-signal", GNU_OPT_ARG, 3},        {"list-signal-handling", GNU_NO_ARG, 4},
    {"debug", GNU_NO_ARG, 'v'},              {"split-string", GNU_REQ_ARG, 'S'},
    {"help", GNU_NO_ARG, 5},                 {"version", GNU_NO_ARG, 6},
};

int smallclueEnvCommand(int argc, char **argv) {
    Env e;
    memset(&e, 0, sizeof(e));
    envUtf8 = gnuUtf8Locale();
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "env", "+C:iS:u:v0", envLongs, sizeof(envLongs) / sizeof(envLongs[0]));
    bool ignoreEnv = false, nul = false, list = false;
    const char *newdir = NULL;
    const char **unsets = (const char **)calloc((size_t)argc + 1, sizeof(char *));
    int nunsets = 0, unsetCap = argc + 1, status = ENV_CANCELED, c;
    char **owned[64];
    int nowned = 0;
    char **av = argv;
    int ac = argc;
    char q[PATH_MAX + 64];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'i': ignoreEnv = true; break;
        case '0': nul = true; break;
        case 'u':
            if (nunsets == unsetCap) {
                unsetCap *= 2;
                unsets = (const char **)realloc(unsets, (size_t)unsetCap * sizeof(char *));
            }
            unsets[nunsets++] = g.arg;
            break;
        case 'C': newdir = g.arg; break;
        case 'v': e.debug = true; break;
        case 1: if (!envSignalAction(&e, g.arg, true)) goto try; break;
        case 2: if (!envSignalAction(&e, g.arg, false)) goto try; break;
        case 3: if (!envBlock(&e, g.arg)) goto try; break;
        case 4: list = true; break;
        case 'S': {
            /* the words replace the option, and options are read again */
            int n = 0;
            char **words = envBuildArgv(&e, g.arg, &n);
            if (!words) goto done;
            if (e.debug && n > 0) {
                char q2[512];
                envDev(&e, "split -S:  %s\n", envQuote(g.arg, q2, sizeof(q2)));
                envDev(&e, " into:    %s\n", envQuote(words[0], q2, sizeof(q2)));
                for (int i = 1; i < n; i++) envDev(&e, "     &    %s\n", envQuote(words[i], q2, sizeof(q2)));
            }
            int rest = g.nops ? 0 : ac - g.ind;
            char **next = (char **)calloc((size_t)(1 + n + rest + 1), sizeof(char *));
            next[0] = av[0];
            for (int i = 0; i < n; i++) next[1 + i] = words[i];
            for (int i = 0; i < rest; i++) next[1 + n + i] = av[g.ind + i];
            if (nowned < 64) owned[nowned++] = words;
            if (nowned < 64) owned[nowned++] = next;
            av = next;
            ac = 1 + n + rest;
            gnuGetoptFree(&g);
            gnuGetoptInit(&g, ac, av, "env", "+C:iS:u:v0", envLongs, sizeof(envLongs) / sizeof(envLongs[0]));
            break;
        }
        case 5:
            fputs("Usage: env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]\n"
                  "Set each NAME to VALUE in the environment and run COMMAND.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -i, --ignore-environment  start with an empty environment\n"
                  "  -0, --null           end each output line with NUL, not newline\n"
                  "  -u, --unset=NAME     remove variable from the environment\n"
                  "  -C, --chdir=DIR      change working directory to DIR\n"
                  "  -S, --split-string=S  process and split S into separate arguments;\n"
                  "                        used to pass multiple arguments on shebang lines\n"
                  "      --block-signal[=SIG]    block delivery of SIG signal(s) to COMMAND\n"
                  "      --default-signal[=SIG]  reset handling of SIG signal(s) to the default\n"
                  "      --ignore-signal[=SIG]   set handling of SIG signal(s) to do nothing\n"
                  "      --list-signal-handling  list non default signal handling to stderr\n"
                  "  -v, --debug          print verbose information for each processing step\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n\n"
                  "A mere - implies -i.  If no COMMAND, print the resulting environment.\n",
                  stdout);
            status = 0;
            goto done;
        case 6: puts("env (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    {
        int ind = 0;
        char **ops = g.ops;
        int nops = g.nops;
        if (ind < nops && !strcmp(ops[ind], "-")) {
            ignoreEnv = true;
            ind++;
        }
        if (ignoreEnv) {
            envDev(&e, "cleaning environ\n");
            smallclueAppClearEnv();
        } else {
            for (int i = 0; i < nunsets; i++) {
                envDev(&e, "unset:    %s\n", unsets[i]);
                if (!*unsets[i] || strchr(unsets[i], '=')) errno = EINVAL;
                if (!*unsets[i] || strchr(unsets[i], '=') || unsetenv(unsets[i]) != 0) {
                    fprintf(stderr, "env: cannot unset %s: %s\n", envQuote(unsets[i], q, sizeof(q)),
                            strerror(errno));
                    goto done;
                }
            }
        }
        for (; ind < nops && strchr(ops[ind], '='); ind++) {
            envDev(&e, "setenv:   %s\n", ops[ind]);
            /* setenv copies (argv may not outlive an in-process run); only
             * GNU's "=x" -- no name -- needs putenv, given a copy */
            char *name = strdup(ops[ind]);
            char *eq = strchr(name, '=');
            *eq = '\0';
            int rc = *name ? setenv(name, eq + 1, 1) : putenv(strdup(ops[ind]));
            if (rc != 0) {
                fprintf(stderr, "env: cannot set %s: %s\n", envQuote(name, q, sizeof(q)), strerror(errno));
                free(name);
                goto done;
            }
            free(name);
        }
        bool program = ind < nops;
        if (nul && program) {
            fputs("env: cannot specify --null (-0) with command\n", stderr);
            goto try;
        }
        if (newdir && !program) {
            fputs("env: must specify command with --chdir (-C)\n", stderr);
            goto try;
        }
        if (!program) {
            extern char **environ;
            for (char **p = environ; p && *p; p++) printf("%s%c", *p, nul ? '\0' : '\n');
            status = 0;
            goto done;
        }
        if (!envApplySignals(&e, list)) goto done;
        if (newdir) {
            envDev(&e, "chdir:    %s\n", gnuQuote(newdir, q, sizeof(q)));
            if (chdir(newdir) != 0) {
                fprintf(stderr, "env: cannot change directory to %s: %s\n", gnuQuote(newdir, q, sizeof(q)),
                        strerror(errno));
                goto done;
            }
        }
        char **cmd = &ops[ind];
        if (e.debug) {
            envDev(&e, "executing: %s\n", cmd[0]);
            for (int i = 0; cmd[i]; i++) envDev(&e, "   arg[%d]= %s\n", i, envQuote(cmd[i], q, sizeof(q)));
        }
        fflush(stdout);
        char resolved[PATH_MAX];
        if (smallclueAppResolveExec(cmd[0], resolved, sizeof(resolved))) execv(resolved, cmd);
        execvp(cmd[0], cmd);
        int err = errno;
        status = err == ENOENT ? ENV_ENOENT : ENV_CANNOT_INVOKE;
        fprintf(stderr, "env: %s: %s\n", envQuote(cmd[0], q, sizeof(q)), strerror(err));
        if (status == ENV_ENOENT && strpbrk(cmd[0], " \t\n\v\f\r"))
            fputs("env: use -[v]S to pass options in shebang lines\n", stderr);
        goto done;
    }
try:
    fputs("Try 'env --help' for more information.\n", stderr);
    status = ENV_CANCELED;
done:
    free(unsets);
    gnuGetoptFree(&g);
    /* words handed to putenv stay; only the vectors go */
    for (int i = 0; i < nowned; i++) free(owned[i]);
    fflush(stdout);
    return status;
}

/* printenv [-0] [VARIABLE]...: GNU coreutils'. With no names, every
 * variable as NAME=value; with names, each one's value, and exit status 1
 * if any of them is unset. -0 (--null) ends each with NUL, not newline. */
int smallcluePrintenvCommand(int argc, char **argv) {
    extern char **environ;
    char end = '\n';
    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "-0") == 0 || strcmp(argv[i], "--null") == 0) {
            end = '\0';
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: printenv [OPTION]... [VARIABLE]...\n");
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1]) {
            fprintf(stderr, "printenv: invalid option -- '%s'\n", argv[i] + 1);
            return 2;
        } else {
            break;
        }
    }
    if (i >= argc) {
        for (char **e = environ; e && *e; e++) {
            fputs(*e, stdout);
            fputc(end, stdout);
        }
        return 0;
    }
    int status = 0;
    for (; i < argc; i++) {
        const char *v = strchr(argv[i], '=') ? NULL : getenv(argv[i]);
        if (!v) {
            status = 1;
            continue;
        }
        fputs(v, stdout);
        fputc(end, stdout);
    }
    return status;
}
