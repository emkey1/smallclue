/* Shell builtins: POSIX special builtins plus the BusyBox ash regulars. */

#include "sh_interp.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <unistd.h>

/* From sh_exec.c */
int shExecArgv(ShInterp *interp, int argc, char **argv);
int shExecReplace(ShInterp *interp, char **argv);
void shInstallTrapHandler(ShInterp *interp, int sig);
char *shPathSearch(ShInterp *interp, const char *name);

#include "../smallclue.h"

/* ---- helpers ------------------------------------------------------------- */

static bool isValidName(const char *name) {
    if (!name || !*name) {
        return false;
    }
    if (!isalpha((unsigned char)name[0]) && name[0] != '_') {
        return false;
    }
    for (const char *p = name + 1; *p; ++p) {
        if (!isalnum((unsigned char)*p) && *p != '_') {
            return false;
        }
    }
    return true;
}

/* ---- trivial ------------------------------------------------------------- */

static int builtinTrue(ShInterp *interp, int argc, char **argv) {
    (void)interp; (void)argc; (void)argv;
    return 0;
}

static int builtinFalse(ShInterp *interp, int argc, char **argv) {
    (void)interp; (void)argc; (void)argv;
    return 1;
}

/* ---- echo / printf -------------------------------------------------------- */

static int builtinEcho(ShInterp *interp, int argc, char **argv) {
    (void)interp;
    bool newline = true;
    bool interpret = false;
    int i = 1;
    for (; i < argc; ++i) {
        const char *a = argv[i];
        if (a[0] != '-' || a[1] == '\0') {
            break;
        }
        bool all_flags = true;
        for (const char *p = a + 1; *p; ++p) {
            if (*p != 'n' && *p != 'e' && *p != 'E') {
                all_flags = false;
                break;
            }
        }
        if (!all_flags) {
            break;
        }
        for (const char *p = a + 1; *p; ++p) {
            if (*p == 'n') newline = false;
            else if (*p == 'e') interpret = true;
            else if (*p == 'E') interpret = false;
        }
    }
    bool stop = false;
    for (; i < argc && !stop; ++i) {
        const char *a = argv[i];
        if (!interpret) {
            fputs(a, stdout);
        } else {
            for (const char *p = a; *p; ++p) {
                if (*p != '\\') {
                    fputc(*p, stdout);
                    continue;
                }
                p++;
                switch (*p) {
                    case 'a': fputc('\a', stdout); break;
                    case 'b': fputc('\b', stdout); break;
                    case 'c': stop = true; newline = false; break;
                    case 'e': fputc('\033', stdout); break;
                    case 'f': fputc('\f', stdout); break;
                    case 'n': fputc('\n', stdout); break;
                    case 'r': fputc('\r', stdout); break;
                    case 't': fputc('\t', stdout); break;
                    case 'v': fputc('\v', stdout); break;
                    case '\\': fputc('\\', stdout); break;
                    case '0': {
                        int val = 0, digits = 0;
                        while (digits < 3 && p[1] >= '0' && p[1] <= '7') {
                            val = val * 8 + (p[1] - '0');
                            p++;
                            digits++;
                        }
                        fputc(val, stdout);
                        break;
                    }
                    case '\0': fputc('\\', stdout); p--; break;
                    default: fputc('\\', stdout); fputc(*p, stdout); break;
                }
                if (stop) {
                    break;
                }
            }
        }
        if (i + 1 < argc && !stop) {
            fputc(' ', stdout);
        }
    }
    if (newline) {
        fputc('\n', stdout);
    }
    fflush(stdout);
    return 0;
}

/* Expand printf %b / \escapes in a string; returns malloc'd. */
static char *printfUnescape(const char *s, bool *stop) {
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        if (s[i] != '\\') {
            out[j++] = s[i];
            continue;
        }
        i++;
        switch (s[i]) {
            case 'a': out[j++] = '\a'; break;
            case 'b': out[j++] = '\b'; break;
            case 'c': if (stop) *stop = true; out[j] = '\0'; return out;
            case 'e': out[j++] = '\033'; break;
            case 'f': out[j++] = '\f'; break;
            case 'n': out[j++] = '\n'; break;
            case 'r': out[j++] = '\r'; break;
            case 't': out[j++] = '\t'; break;
            case 'v': out[j++] = '\v'; break;
            case '\\': out[j++] = '\\'; break;
            case '\'': out[j++] = '\''; break;
            case '"': out[j++] = '"'; break;
            case '0': case '1': case '2': case '3':
            case '4': case '5': case '6': case '7': {
                int val = 0, digits = 0;
                while (digits < 3 && s[i] >= '0' && s[i] <= '7') {
                    val = val * 8 + (s[i] - '0');
                    i++;
                    digits++;
                }
                i--;
                out[j++] = (char)val;
                break;
            }
            case 'x': {
                int val = 0, digits = 0;
                i++;
                while (digits < 2 && isxdigit((unsigned char)s[i])) {
                    val = val * 16 + (isdigit((unsigned char)s[i]) ? s[i] - '0'
                                                                   : (tolower(s[i]) - 'a' + 10));
                    i++;
                    digits++;
                }
                i--;
                if (digits > 0) {
                    out[j++] = (char)val;
                } else {
                    out[j++] = '\\';
                    out[j++] = 'x';
                }
                break;
            }
            case '\0': out[j++] = '\\'; i--; break;
            default: out[j++] = '\\'; out[j++] = s[i]; break;
        }
    }
    out[j] = '\0';
    return out;
}

/* Decode ONE backslash escape at s (s[0]=='\\'), write its expansion to
 * stdout, and return the number of input bytes consumed. */
static size_t printfDecodeEscape(const char *s, bool *stop) {
    char c = s[1];
    switch (c) {
        case 'a': fputc('\a', stdout); return 2;
        case 'b': fputc('\b', stdout); return 2;
        case 'c': if (stop) *stop = true; return 2;
        case 'e': fputc('\033', stdout); return 2;
        case 'f': fputc('\f', stdout); return 2;
        case 'n': fputc('\n', stdout); return 2;
        case 'r': fputc('\r', stdout); return 2;
        case 't': fputc('\t', stdout); return 2;
        case 'v': fputc('\v', stdout); return 2;
        case '\\': fputc('\\', stdout); return 2;
        case '"': fputc('"', stdout); return 2;
        case '\'': fputc('\'', stdout); return 2;
        case '\0': fputc('\\', stdout); return 1;
        default:
            if (c >= '0' && c <= '7') {
                int val = 0;
                size_t i = 1;
                int digits = 0;
                while (digits < 3 && s[i] >= '0' && s[i] <= '7') {
                    val = val * 8 + (s[i] - '0');
                    i++;
                    digits++;
                }
                fputc(val, stdout);
                return i;
            }
            if (c == 'x' && isxdigit((unsigned char)s[2])) {
                int val = 0;
                size_t i = 2;
                int digits = 0;
                while (digits < 2 && isxdigit((unsigned char)s[i])) {
                    val = val * 16 + (isdigit((unsigned char)s[i])
                                          ? s[i] - '0'
                                          : (tolower((unsigned char)s[i]) - 'a' + 10));
                    i++;
                    digits++;
                }
                fputc(val, stdout);
                return i;
            }
            fputc('\\', stdout);
            fputc(c, stdout);
            return 2;
    }
}

static int builtinPrintf(ShInterp *interp, int argc, char **argv) {
    (void)interp;
    if (argc < 2) {
        fprintf(stderr, "printf: usage: printf format [arguments]\n");
        return 1;
    }
    const char *format = argv[1];
    int argi = 2;
    int ret = 0;

    do {
        int args_used = 0;
        for (const char *p = format; *p; ++p) {
            if (*p == '\\') {
                bool stop = false;
                size_t adv = printfDecodeEscape(p, &stop);
                if (stop) {
                    fflush(stdout);
                    return ret;
                }
                p += adv - 1;
                continue;
            }
            if (*p != '%') {
                fputc(*p, stdout);
                continue;
            }
            p++;
            if (*p == '%') {
                fputc('%', stdout);
                continue;
            }
            /* parse flags/width/precision */
            char spec[64];
            size_t sn = 0;
            spec[sn++] = '%';
            while (*p && strchr("-+ #0", *p) && sn < sizeof(spec) - 8) {
                spec[sn++] = *p++;
            }
            while (*p && (isdigit((unsigned char)*p) || *p == '.') && sn < sizeof(spec) - 8) {
                spec[sn++] = *p++;
            }
            char conv = *p;
            const char *arg = (argi < argc) ? argv[argi] : NULL;
            switch (conv) {
                case 'd': case 'i': {
                    long long v = 0;
                    if (arg) {
                        args_used++;
                        argi++;
                        if (arg[0] == '\'' || arg[0] == '"') {
                            v = (unsigned char)arg[1];
                        } else {
                            errno = 0;
                            char *end = NULL;
                            v = strtoll(arg, &end, 0);
                            if (end && *end) {
                                fprintf(stderr, "printf: %s: not completely converted\n", arg);
                                ret = 1;
                            }
                        }
                    }
                    spec[sn++] = 'l';
                    spec[sn++] = 'l';
                    spec[sn++] = conv;
                    spec[sn] = '\0';
                    printf(spec, v);
                    break;
                }
                case 'o': case 'u': case 'x': case 'X': {
                    unsigned long long v = 0;
                    if (arg) {
                        args_used++;
                        argi++;
                        if (arg[0] == '\'' || arg[0] == '"') {
                            v = (unsigned char)arg[1];
                        } else {
                            char *end = NULL;
                            long long sv = strtoll(arg, &end, 0);
                            v = (unsigned long long)sv;
                            if (end && *end) {
                                fprintf(stderr, "printf: %s: not completely converted\n", arg);
                                ret = 1;
                            }
                        }
                    }
                    spec[sn++] = 'l';
                    spec[sn++] = 'l';
                    spec[sn++] = conv;
                    spec[sn] = '\0';
                    printf(spec, v);
                    break;
                }
                case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': {
                    double v = 0;
                    if (arg) {
                        args_used++;
                        argi++;
                        v = strtod(arg, NULL);
                    }
                    spec[sn++] = conv;
                    spec[sn] = '\0';
                    printf(spec, v);
                    break;
                }
                case 'c': {
                    if (arg) {
                        args_used++;
                        argi++;
                        spec[sn++] = 'c';
                        spec[sn] = '\0';
                        printf(spec, arg[0]);
                    }
                    break;
                }
                case 's': {
                    spec[sn++] = 's';
                    spec[sn] = '\0';
                    if (arg) {
                        args_used++;
                        argi++;
                    }
                    printf(spec, arg ? arg : "");
                    break;
                }
                case 'b': {
                    bool stop = false;
                    char *un = printfUnescape(arg ? arg : "", &stop);
                    if (arg) {
                        args_used++;
                        argi++;
                    }
                    spec[sn++] = 's';
                    spec[sn] = '\0';
                    printf(spec, un);
                    free(un);
                    if (stop) {
                        fflush(stdout);
                        return ret;
                    }
                    break;
                }
                default:
                    fprintf(stderr, "printf: %%%c: invalid directive\n", conv ? conv : '?');
                    fflush(stdout);
                    return 1;
            }
            if (!*p) {
                break;
            }
        }
        /* Cycle the format while arguments remain (POSIX). */
        if (args_used == 0) {
            break;
        }
    } while (argi < argc);
    fflush(stdout);
    return ret;
}

/* ---- test / [ -------------------------------------------------------------- */

typedef struct {
    char **argv;
    int argc;
    int pos;
} TestParser;

static bool testOr(TestParser *tp, int *err);

static const char *testPeek(TestParser *tp) {
    return tp->pos < tp->argc ? tp->argv[tp->pos] : NULL;
}

static const char *testNext(TestParser *tp) {
    return tp->pos < tp->argc ? tp->argv[tp->pos++] : NULL;
}

static bool testFileCheck(char op, const char *path) {
    struct stat st;
    switch (op) {
        case 'e': return stat(path, &st) == 0;
        case 'f': return stat(path, &st) == 0 && S_ISREG(st.st_mode);
        case 'd': return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
        case 'b': return stat(path, &st) == 0 && S_ISBLK(st.st_mode);
        case 'c': return stat(path, &st) == 0 && S_ISCHR(st.st_mode);
        case 'p': return stat(path, &st) == 0 && S_ISFIFO(st.st_mode);
        case 'S': return stat(path, &st) == 0 && S_ISSOCK(st.st_mode);
        case 'L':
        case 'h': return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
        case 's': return stat(path, &st) == 0 && st.st_size > 0;
        case 'r': return access(path, R_OK) == 0;
        case 'w': return access(path, W_OK) == 0;
        case 'x': return access(path, X_OK) == 0;
        case 'u': return stat(path, &st) == 0 && (st.st_mode & S_ISUID);
        case 'g': return stat(path, &st) == 0 && (st.st_mode & S_ISGID);
        case 'k': return stat(path, &st) == 0 && (st.st_mode & S_ISVTX);
        default: return false;
    }
}

static bool testPrimary(TestParser *tp, int *err) {
    const char *tok = testNext(tp);
    if (!tok) {
        *err = 1;
        return false;
    }
    if (strcmp(tok, "!") == 0) {
        return !testPrimary(tp, err);
    }
    if (strcmp(tok, "(") == 0) {
        bool v = testOr(tp, err);
        const char *close = testNext(tp);
        if (!close || strcmp(close, ")") != 0) {
            *err = 1;
        }
        return v;
    }
    /* unary operators */
    if (tok[0] == '-' && tok[1] && !tok[2] && testPeek(tp)) {
        char op = tok[1];
        if (strchr("efdbcpSLhsrwxugk", op)) {
            return testFileCheck(op, testNext(tp));
        }
        if (op == 'z') {
            return testNext(tp)[0] == '\0';
        }
        if (op == 'n') {
            return testNext(tp)[0] != '\0';
        }
        if (op == 't') {
            const char *fd = testNext(tp);
            return isatty(atoi(fd)) != 0;
        }
    }
    /* binary operators */
    const char *op = testPeek(tp);
    if (op) {
        const char *lhs = tok;
        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
            testNext(tp);
            const char *rhs = testNext(tp);
            return rhs && strcmp(lhs, rhs) == 0;
        }
        if (strcmp(op, "!=") == 0) {
            testNext(tp);
            const char *rhs = testNext(tp);
            return rhs && strcmp(lhs, rhs) != 0;
        }
        static const struct {
            const char *name;
            int kind;
        } numops[] = {
            {"-eq", 0}, {"-ne", 1}, {"-gt", 2}, {"-ge", 3}, {"-lt", 4}, {"-le", 5},
        };
        for (size_t k = 0; k < sizeof(numops) / sizeof(numops[0]); ++k) {
            if (strcmp(op, numops[k].name) == 0) {
                testNext(tp);
                const char *rhs = testNext(tp);
                if (!rhs) {
                    *err = 1;
                    return false;
                }
                long long a = strtoll(lhs, NULL, 10);
                long long b = strtoll(rhs, NULL, 10);
                switch (numops[k].kind) {
                    case 0: return a == b;
                    case 1: return a != b;
                    case 2: return a > b;
                    case 3: return a >= b;
                    case 4: return a < b;
                    case 5: return a <= b;
                }
            }
        }
        if (strcmp(op, "-nt") == 0 || strcmp(op, "-ot") == 0 || strcmp(op, "-ef") == 0) {
            testNext(tp);
            const char *rhs = testNext(tp);
            struct stat sa, sb;
            bool ha = rhs && stat(lhs, &sa) == 0;
            bool hb = rhs && stat(rhs, &sb) == 0;
            if (strcmp(op, "-ef") == 0) {
                return ha && hb && sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
            }
            if (strcmp(op, "-nt") == 0) {
                return ha && (!hb || sa.st_mtime > sb.st_mtime);
            }
            return hb && (!ha || sa.st_mtime < sb.st_mtime);
        }
    }
    /* bare string: true if non-empty */
    return tok[0] != '\0';
}

static bool testAnd(TestParser *tp, int *err) {
    bool v = testPrimary(tp, err);
    while (testPeek(tp) && strcmp(testPeek(tp), "-a") == 0) {
        testNext(tp);
        bool rhs = testPrimary(tp, err);
        v = v && rhs;
    }
    return v;
}

static bool testOr(TestParser *tp, int *err) {
    bool v = testAnd(tp, err);
    while (testPeek(tp) && strcmp(testPeek(tp), "-o") == 0) {
        testNext(tp);
        bool rhs = testAnd(tp, err);
        v = v || rhs;
    }
    return v;
}

static int builtinTest(ShInterp *interp, int argc, char **argv) {
    (void)interp;
    int end = argc;
    if (strcmp(argv[0], "[") == 0) {
        if (argc < 2 || strcmp(argv[argc - 1], "]") != 0) {
            fprintf(stderr, "[: missing ']'\n");
            return 2;
        }
        end = argc - 1;
    }
    if (end <= 1) {
        return 1;
    }
    TestParser tp = {argv + 1, end - 1, 0};
    int err = 0;
    bool v = testOr(&tp, &err);
    if (err || tp.pos != tp.argc) {
        fprintf(stderr, "test: syntax error\n");
        return 2;
    }
    return v ? 0 : 1;
}

/* ---- cd / pwd ---------------------------------------------------------------- */

static int builtinPwd(ShInterp *interp, int argc, char **argv) {
    (void)argc; (void)argv;
    char buf[PATH_MAX];
    const char *logical = shVarGet(interp, "PWD");
    bool use_physical = (argc > 1 && strcmp(argv[1], "-P") == 0);
    if (!use_physical && logical && logical[0] == '/') {
        struct stat a, b;
        if (stat(logical, &a) == 0 && stat(".", &b) == 0 &&
            a.st_dev == b.st_dev && a.st_ino == b.st_ino) {
            printf("%s\n", logical);
            return 0;
        }
    }
    if (getcwd(buf, sizeof(buf))) {
        printf("%s\n", buf);
        return 0;
    }
    fprintf(stderr, "pwd: %s\n", strerror(errno));
    return 1;
}

static int builtinCd(ShInterp *interp, int argc, char **argv) {
    /* `target` may point into the variable table (OLDPWD/HOME), which this
     * function itself updates -- keep an owned copy. */
    char target_buf[PATH_MAX];
    const char *target = NULL;
    bool physical = false;
    int i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "-P") == 0) {
            physical = true;
        } else if (strcmp(argv[i], "-L") == 0) {
            physical = false;
        } else {
            break;
        }
    }
    bool print_dir = false;
    if (i < argc) {
        target = argv[i];
        if (strcmp(target, "-") == 0) {
            const char *oldpwd_val = shVarGet(interp, "OLDPWD");
            if (!oldpwd_val) {
                fprintf(stderr, "cd: OLDPWD not set\n");
                return 1;
            }
            snprintf(target_buf, sizeof(target_buf), "%s", oldpwd_val);
            target = target_buf;
            print_dir = true;
        }
    } else {
        const char *home = shVarGet(interp, "HOME");
        if (!home) {
            fprintf(stderr, "cd: HOME not set\n");
            return 1;
        }
        snprintf(target_buf, sizeof(target_buf), "%s", home);
        target = target_buf;
    }

    /* OLDPWD keeps the logical PWD so `cd -` round-trips symlinked paths. */
    char oldpwd[PATH_MAX];
    const char *logical_pwd = shVarGet(interp, "PWD");
    if (logical_pwd && logical_pwd[0] == '/') {
        snprintf(oldpwd, sizeof(oldpwd), "%s", logical_pwd);
    } else if (!getcwd(oldpwd, sizeof(oldpwd))) {
        oldpwd[0] = '\0';
    }
    if (chdir(target) != 0) {
        fprintf(stderr, "cd: %s: %s\n", target, strerror(errno));
        return 1;
    }
    if (oldpwd[0]) {
        shVarSet(interp, "OLDPWD", oldpwd, true);
    }
    char newpwd[PATH_MAX];
    if (physical || target[0] != '/') {
        if (getcwd(newpwd, sizeof(newpwd))) {
            shVarSet(interp, "PWD", newpwd, true);
        }
    } else {
        shVarSet(interp, "PWD", target, true);
    }
    if (print_dir) {
        const char *pwd = shVarGet(interp, "PWD");
        printf("%s\n", pwd ? pwd : target);
    }
    return 0;
}

/* ---- variable management -------------------------------------------------------- */

static int builtinExport(ShInterp *interp, int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-p") == 0)) {
        for (ShVar *v = interp->vars; v; v = v->next) {
            if (v->exported) {
                if (v->value) {
                    printf("export %s='%s'\n", v->name, v->value);
                } else {
                    printf("export %s\n", v->name);
                }
            }
        }
        return 0;
    }
    int status = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0) {
            continue;
        }
        char *eq = strchr(argv[i], '=');
        if (eq) {
            char *name = strndup(argv[i], (size_t)(eq - argv[i]));
            if (!isValidName(name)) {
                fprintf(stderr, "export: %s: not a valid identifier\n", name);
                status = 1;
            } else {
                shVarExport(interp, name, eq + 1);
            }
            free(name);
        } else {
            if (!isValidName(argv[i])) {
                fprintf(stderr, "export: %s: not a valid identifier\n", argv[i]);
                status = 1;
            } else {
                shVarExport(interp, argv[i], NULL);
            }
        }
    }
    return status;
}

static int builtinReadonly(ShInterp *interp, int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-p") == 0)) {
        for (ShVar *v = interp->vars; v; v = v->next) {
            if (v->read_only) {
                if (v->value) {
                    printf("readonly %s='%s'\n", v->name, v->value);
                } else {
                    printf("readonly %s\n", v->name);
                }
            }
        }
        return 0;
    }
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0) {
            continue;
        }
        char *eq = strchr(argv[i], '=');
        if (eq) {
            char *name = strndup(argv[i], (size_t)(eq - argv[i]));
            shVarMakeReadOnly(interp, name, eq + 1);
            free(name);
        } else {
            shVarMakeReadOnly(interp, argv[i], NULL);
        }
    }
    return 0;
}

static int builtinUnset(ShInterp *interp, int argc, char **argv) {
    bool functions = false;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; ++i) {
        if (strcmp(argv[i], "-f") == 0) {
            functions = true;
        } else if (strcmp(argv[i], "-v") == 0) {
            functions = false;
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            fprintf(stderr, "unset: bad option: %s\n", argv[i]);
            return 2;
        }
    }
    int status = 0;
    for (; i < argc; ++i) {
        if (functions) {
            shFuncUndefine(interp, argv[i]);
        } else {
            if (shVarUnset(interp, argv[i]) != 0) {
                status = 1;
            }
        }
    }
    return status;
}

static int builtinLocal(ShInterp *interp, int argc, char **argv) {
    if (!interp->func_frames) {
        fprintf(stderr, "local: not in a function\n");
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            char *name = strndup(argv[i], (size_t)(eq - argv[i]));
            shVarMarkLocal(interp, name);
            shVarSet(interp, name, eq + 1, false);
            free(name);
        } else {
            shVarMarkLocal(interp, argv[i]);
            shVarSet(interp, argv[i], "", false);
        }
    }
    return 0;
}

/* ---- set / shift ------------------------------------------------------------------ */

static int applySetOption(ShInterp *interp, char opt, bool value) {
    switch (opt) {
        case 'e': interp->opt_errexit = value; break;
        case 'u': interp->opt_nounset = value; break;
        case 'x': interp->opt_xtrace = value; break;
        case 'f': interp->opt_noglob = value; break;
        case 'n': interp->opt_noexec = value; break;
        case 'C': interp->opt_noclobber = value; break;
        case 'a': interp->opt_allexport = value; break;
        case 'v': interp->opt_verbose = value; break;
        case 'm': interp->opt_monitor = value; break;
        case 'h': break; /* hash on use: accepted, no-op */
        case 'b': break; /* async notify: accepted, no-op */
        default:
            return 1;
    }
    return 0;
}

static int applySetLongOption(ShInterp *interp, const char *name, bool value) {
    if (strcmp(name, "errexit") == 0) interp->opt_errexit = value;
    else if (strcmp(name, "nounset") == 0) interp->opt_nounset = value;
    else if (strcmp(name, "xtrace") == 0) interp->opt_xtrace = value;
    else if (strcmp(name, "noglob") == 0) interp->opt_noglob = value;
    else if (strcmp(name, "noexec") == 0) interp->opt_noexec = value;
    else if (strcmp(name, "noclobber") == 0) interp->opt_noclobber = value;
    else if (strcmp(name, "allexport") == 0) interp->opt_allexport = value;
    else if (strcmp(name, "verbose") == 0) interp->opt_verbose = value;
    else if (strcmp(name, "monitor") == 0) interp->opt_monitor = value;
    else if (strcmp(name, "pipefail") == 0) interp->opt_pipefail = value;
    else if (strcmp(name, "ignoreeof") == 0) { /* accepted, no-op */ }
    else if (strcmp(name, "vi") == 0 || strcmp(name, "emacs") == 0) { /* no-op */ }
    else {
        fprintf(stderr, "set: -o %s: unknown option\n", name);
        return 1;
    }
    return 0;
}

static void setPositionalParams(ShInterp *interp, char **args, int count) {
    for (int i = 0; i < interp->param_count; ++i) {
        free(interp->params[i]);
    }
    free(interp->params);
    interp->params = (char **)calloc(count > 0 ? (size_t)count : 1, sizeof(char *));
    for (int i = 0; i < count; ++i) {
        interp->params[i] = strdup(args[i]);
    }
    interp->param_count = count;
}

static int builtinSet(ShInterp *interp, int argc, char **argv) {
    if (argc == 1) {
        for (ShVar *v = interp->vars; v; v = v->next) {
            if (v->value) {
                printf("%s='%s'\n", v->name, v->value);
            }
        }
        return 0;
    }
    int i = 1;
    for (; i < argc; ++i) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            i++;
            setPositionalParams(interp, argv + i, argc - i);
            return 0;
        }
        if (a[0] != '-' && a[0] != '+') {
            break;
        }
        bool value = (a[0] == '-');
        if (a[1] == 'o' && a[2] == '\0') {
            if (i + 1 < argc) {
                if (applySetLongOption(interp, argv[++i], value) != 0) {
                    return 1;
                }
            } else {
                /* print option state */
                printf("errexit  \t%s\n", interp->opt_errexit ? "on" : "off");
                printf("nounset  \t%s\n", interp->opt_nounset ? "on" : "off");
                printf("xtrace   \t%s\n", interp->opt_xtrace ? "on" : "off");
                printf("noglob   \t%s\n", interp->opt_noglob ? "on" : "off");
                printf("noclobber\t%s\n", interp->opt_noclobber ? "on" : "off");
                printf("allexport\t%s\n", interp->opt_allexport ? "on" : "off");
                printf("monitor  \t%s\n", interp->opt_monitor ? "on" : "off");
                printf("pipefail \t%s\n", interp->opt_pipefail ? "on" : "off");
            }
            continue;
        }
        for (const char *p = a + 1; *p; ++p) {
            if (applySetOption(interp, *p, value) != 0) {
                fprintf(stderr, "set: -%c: unknown option\n", *p);
                return 2;
            }
        }
    }
    if (i < argc) {
        setPositionalParams(interp, argv + i, argc - i);
    }
    return 0;
}

static int builtinShift(ShInterp *interp, int argc, char **argv) {
    int n = 1;
    if (argc > 1) {
        n = atoi(argv[1]);
    }
    if (n < 0 || n > interp->param_count) {
        fprintf(stderr, "shift: shift count out of range\n");
        return 1;
    }
    for (int i = 0; i < n; ++i) {
        free(interp->params[i]);
    }
    memmove(interp->params, interp->params + n,
            (size_t)(interp->param_count - n) * sizeof(char *));
    interp->param_count -= n;
    return 0;
}

/* ---- control flow ------------------------------------------------------------------- */

static int builtinBreak(ShInterp *interp, int argc, char **argv) {
    if (interp->loop_depth == 0) {
        return 0;
    }
    int n = argc > 1 ? atoi(argv[1]) : 1;
    if (n < 1) {
        n = 1;
    }
    interp->flow = SH_FLOW_BREAK;
    interp->flow_count = n;
    return 0;
}

static int builtinContinue(ShInterp *interp, int argc, char **argv) {
    if (interp->loop_depth == 0) {
        return 0;
    }
    int n = argc > 1 ? atoi(argv[1]) : 1;
    if (n < 1) {
        n = 1;
    }
    interp->flow = SH_FLOW_CONTINUE;
    interp->flow_count = n;
    return 0;
}

static int builtinReturn(ShInterp *interp, int argc, char **argv) {
    int status = argc > 1 ? (atoi(argv[1]) & 0xff) : interp->last_status;
    if (interp->func_depth == 0) {
        /* outside a function: acts like exit in a sourced script */
        interp->flow = SH_FLOW_RETURN;
        interp->exit_status = status;
        return status;
    }
    interp->flow = SH_FLOW_RETURN;
    interp->exit_status = status;
    return status;
}

static int builtinExit(ShInterp *interp, int argc, char **argv) {
    int status = argc > 1 ? (atoi(argv[1]) & 0xff) : interp->last_status;
    interp->flow = SH_FLOW_EXIT;
    interp->exit_status = status;
    return status;
}

/* ---- eval / dot / exec / command ------------------------------------------------------ */

static int builtinEval(ShInterp *interp, int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }
    size_t total = 0;
    for (int i = 1; i < argc; ++i) {
        total += strlen(argv[i]) + 1;
    }
    char *joined = (char *)malloc(total + 1);
    if (!joined) {
        return 1;
    }
    size_t pos = 0;
    for (int i = 1; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        memcpy(joined + pos, argv[i], len);
        pos += len;
        if (i + 1 < argc) {
            joined[pos++] = ' ';
        }
    }
    joined[pos] = '\0';
    int status = shRunString(interp, joined, "eval");
    free(joined);
    return status;
}

static int builtinDot(ShInterp *interp, int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, ".: filename argument required\n");
        return 2;
    }
    const char *path = argv[1];
    char *resolved = NULL;
    if (!strchr(path, '/')) {
        resolved = shPathSearch(interp, path);
        if (!resolved && access(path, R_OK) == 0) {
            resolved = strdup(path);
        }
        if (resolved) {
            path = resolved;
        }
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, ".: %s: %s\n", argv[1], strerror(errno));
        free(resolved);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *source = (char *)malloc((size_t)size + 1);
    if (!source) {
        fclose(f);
        free(resolved);
        return 1;
    }
    size_t got = fread(source, 1, (size_t)size, f);
    source[got] = '\0';
    fclose(f);

    /* Optional extra args become positional params for the sourced script
     * (bash extension BusyBox also has). */
    char **old_params = NULL;
    int old_count = 0;
    bool swapped = false;
    if (argc > 2) {
        old_params = interp->params;
        old_count = interp->param_count;
        interp->params = (char **)calloc((size_t)(argc - 2), sizeof(char *));
        for (int i = 2; i < argc; ++i) {
            interp->params[i - 2] = strdup(argv[i]);
        }
        interp->param_count = argc - 2;
        swapped = true;
    }

    int status = shRunString(interp, source, argv[1]);
    if (interp->flow == SH_FLOW_RETURN) {
        interp->flow = SH_FLOW_NONE;
        status = interp->exit_status;
    }

    if (swapped) {
        for (int i = 0; i < interp->param_count; ++i) {
            free(interp->params[i]);
        }
        free(interp->params);
        interp->params = old_params;
        interp->param_count = old_count;
    }
    free(source);
    free(resolved);
    return status;
}

static int builtinExec(ShInterp *interp, int argc, char **argv) {
    if (argc < 2) {
        return 0; /* redirections (already applied persistently) */
    }
    int status = shExecReplace(interp, argv + 1);
    /* If we get here the exec failed; POSIX: non-interactive shell exits. */
    if (!interp->interactive) {
        interp->flow = SH_FLOW_EXIT;
        interp->exit_status = status;
    }
    return status;
}

static int builtinCommand(ShInterp *interp, int argc, char **argv) {
    int i = 1;
    bool describe = false, verbose = false;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; ++i) {
        if (strcmp(argv[i], "-v") == 0) {
            describe = true;
        } else if (strcmp(argv[i], "-V") == 0) {
            describe = verbose = true;
        } else if (strcmp(argv[i], "-p") == 0) {
            /* default PATH: approximated by regular lookup */
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            break;
        }
    }
    if (i >= argc) {
        return 0;
    }
    if (describe) {
        int status = 0;
        for (; i < argc; ++i) {
            const char *name = argv[i];
            if (shFindBuiltin(name)) {
                if (verbose) {
                    printf("%s is a shell builtin\n", name);
                } else {
                    printf("%s\n", name);
                }
            } else if (shFuncLookup(interp, name)) {
                if (verbose) {
                    printf("%s is a function\n", name);
                } else {
                    printf("%s\n", name);
                }
            } else {
                char *path = shPathSearch(interp, name);
                if (!path && smallclueFindApplet(name)) {
                    if (verbose) {
                        printf("%s is a smallclue applet\n", name);
                    } else {
                        printf("%s\n", name);
                    }
                } else if (path) {
                    if (verbose) {
                        printf("%s is %s\n", name, path);
                    } else {
                        printf("%s\n", path);
                    }
                    free(path);
                } else {
                    if (verbose) {
                        fprintf(stderr, "command: %s: not found\n", name);
                    }
                    status = 1;
                }
            }
        }
        return status;
    }
    return shExecArgv(interp, argc - i, argv + i);
}

static int builtinType(ShInterp *interp, int argc, char **argv) {
    int status = 0;
    for (int i = 1; i < argc; ++i) {
        const char *name = argv[i];
        if (shFindBuiltin(name)) {
            printf("%s is a shell builtin\n", name);
        } else if (shFuncLookup(interp, name)) {
            printf("%s is a shell function\n", name);
        } else if (smallclueFindApplet(name)) {
            printf("%s is a smallclue applet\n", name);
        } else {
            char *path = shPathSearch(interp, name);
            if (path) {
                printf("%s is %s\n", name, path);
                free(path);
            } else {
                fprintf(stderr, "type: %s: not found\n", name);
                status = 1;
            }
        }
    }
    return status;
}

static int builtinHash(ShInterp *interp, int argc, char **argv) {
    (void)interp; (void)argc; (void)argv;
    return 0; /* no command hashing: PATH search is cheap here */
}

/* ---- read ----------------------------------------------------------------------------- */

static int builtinRead(ShInterp *interp, int argc, char **argv) {
    bool raw = false;
    const char *prompt = NULL;
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; ++i) {
        if (strcmp(argv[i], "-r") == 0) {
            raw = true;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            prompt = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            fprintf(stderr, "read: bad option: %s\n", argv[i]);
            return 2;
        }
    }
    if (prompt && isatty(0)) {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    /* Read one line byte-at-a-time so we don't consume beyond the newline. */
    size_t cap = 128, len = 0;
    char *line = (char *)malloc(cap);
    if (!line) {
        return 1;
    }
    bool eof = false;
    for (;;) {
        char c;
        ssize_t r = read(0, &c, 1);
        if (r < 0 && errno == EINTR) {
            shRunPendingTraps(interp);
            if (interp->got_sigint) {
                free(line);
                return 130;
            }
            continue;
        }
        if (r <= 0) {
            eof = true;
            break;
        }
        if (c == '\n') {
            if (!raw && len > 0 && line[len - 1] == '\\') {
                len--; /* line continuation */
                continue;
            }
            break;
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *tmp = (char *)realloc(line, cap);
            if (!tmp) {
                free(line);
                return 1;
            }
            line = tmp;
        }
        line[len++] = c;
    }
    line[len] = '\0';

    /* Backslash removal (unless -r). */
    if (!raw) {
        size_t w = 0;
        for (size_t r2 = 0; r2 < len; ++r2) {
            if (line[r2] == '\\' && r2 + 1 < len) {
                line[w++] = line[++r2];
            } else if (line[r2] != '\\') {
                line[w++] = line[r2];
            }
        }
        line[w] = '\0';
        len = w;
    }

    /* Split into variables by IFS; last var takes the remainder. */
    const char *ifs = shVarGet(interp, "IFS");
    if (!ifs) {
        ifs = " \t\n";
    }
    int nvars = argc - i;
    if (nvars <= 0) {
        shVarSet(interp, "REPLY", line, false);
    } else {
        char *p = line;
        for (int v = 0; v < nvars; ++v) {
            /* skip leading IFS whitespace */
            while (*p && strchr(ifs, *p) && (*p == ' ' || *p == '\t' || *p == '\n')) {
                p++;
            }
            if (v == nvars - 1) {
                /* strip trailing IFS whitespace */
                size_t plen = strlen(p);
                while (plen > 0 && strchr(ifs, p[plen - 1]) &&
                       (p[plen - 1] == ' ' || p[plen - 1] == '\t' || p[plen - 1] == '\n')) {
                    p[--plen] = '\0';
                }
                shVarSet(interp, argv[i + v], p, false);
                break;
            }
            char *start = p;
            while (*p && !strchr(ifs, *p)) {
                p++;
            }
            if (*p) {
                *p++ = '\0';
            }
            shVarSet(interp, argv[i + v], start, false);
        }
    }
    free(line);
    return eof && len == 0 ? 1 : 0;
}

/* ---- trap ------------------------------------------------------------------------------ */

typedef struct {
    const char *name;
    int sig;
} SigName;

static const SigName kSigNames[] = {
    {"EXIT", 0},   {"HUP", SIGHUP},   {"INT", SIGINT},   {"QUIT", SIGQUIT},
    {"ILL", SIGILL}, {"TRAP", SIGTRAP}, {"ABRT", SIGABRT}, {"FPE", SIGFPE},
    {"KILL", SIGKILL}, {"BUS", SIGBUS}, {"SEGV", SIGSEGV}, {"SYS", SIGSYS},
    {"PIPE", SIGPIPE}, {"ALRM", SIGALRM}, {"TERM", SIGTERM}, {"URG", SIGURG},
    {"STOP", SIGSTOP}, {"TSTP", SIGTSTP}, {"CONT", SIGCONT}, {"CHLD", SIGCHLD},
    {"TTIN", SIGTTIN}, {"TTOU", SIGTTOU}, {"IO", SIGIO},   {"XCPU", SIGXCPU},
    {"XFSZ", SIGXFSZ}, {"VTALRM", SIGVTALRM}, {"PROF", SIGPROF},
    {"WINCH", SIGWINCH}, {"USR1", SIGUSR1}, {"USR2", SIGUSR2},
};

static int signalFromName(const char *name) {
    if (isdigit((unsigned char)name[0])) {
        return atoi(name);
    }
    if (strncasecmp(name, "SIG", 3) == 0) {
        name += 3;
    }
    for (size_t i = 0; i < sizeof(kSigNames) / sizeof(kSigNames[0]); ++i) {
        if (strcasecmp(kSigNames[i].name, name) == 0) {
            return kSigNames[i].sig;
        }
    }
    return -1;
}

static const char *signalToName(int sig) {
    for (size_t i = 0; i < sizeof(kSigNames) / sizeof(kSigNames[0]); ++i) {
        if (kSigNames[i].sig == sig) {
            return kSigNames[i].name;
        }
    }
    return NULL;
}

static int builtinTrap(ShInterp *interp, int argc, char **argv) {
    if (argc == 1) {
        for (int sig = 0; sig < interp->trap_count; ++sig) {
            if (interp->traps[sig]) {
                const char *name = signalToName(sig);
                if (name) {
                    printf("trap -- '%s' %s\n", interp->traps[sig], name);
                } else {
                    printf("trap -- '%s' %d\n", interp->traps[sig], sig);
                }
            }
        }
        return 0;
    }
    int i = 1;
    if (strcmp(argv[i], "--") == 0) {
        i++;
    }
    if (i >= argc) {
        return 0;
    }
    const char *action = argv[i];
    bool reset_mode = false;
    /* `trap 15` / `trap - INT`: reset to default */
    if (strcmp(action, "-") == 0) {
        reset_mode = true;
        i++;
    } else if (isdigit((unsigned char)action[0]) && argc == i + 1) {
        reset_mode = true;
    } else {
        i++;
    }
    if (i >= argc && !reset_mode) {
        return 0;
    }
    int status = 0;
    for (; i < argc; ++i) {
        int sig = signalFromName(argv[i]);
        if (sig < 0 || sig >= interp->trap_count) {
            fprintf(stderr, "trap: %s: bad signal\n", argv[i]);
            status = 1;
            continue;
        }
        free(interp->traps[sig]);
        if (reset_mode) {
            interp->traps[sig] = NULL;
            if (sig > 0) {
                signal(sig, SIG_DFL);
            }
        } else {
            interp->traps[sig] = strdup(action);
            if (sig > 0) {
                if (action[0] == '\0') {
                    signal(sig, SIG_IGN);
                } else {
                    shInstallTrapHandler(interp, sig);
                }
            }
        }
    }
    return status;
}

/* ---- jobs / wait / fg / bg / kill --------------------------------------------------------- */

static int builtinJobs(ShInterp *interp, int argc, char **argv) {
    bool show_pids = argc > 1 && strcmp(argv[1], "-l") == 0;
    shReapJobs(interp, false);
    for (ShJob *j = interp->jobs; j; j = j->next) {
        shPrintJob(interp, j, show_pids);
    }
    /* Remove Done jobs after reporting. */
    ShJob *j = interp->jobs;
    while (j) {
        ShJob *next = j->next;
        if (j->state == SH_JOB_DONE) {
            shJobRemove(interp, j);
        }
        j = next;
    }
    return 0;
}

static int builtinWait(ShInterp *interp, int argc, char **argv) {
    if (argc == 1) {
        shReapJobs(interp, true);
        ShJob *j = interp->jobs;
        while (j) {
            ShJob *next = j->next;
            if (j->state == SH_JOB_DONE) {
                shJobRemove(interp, j);
            }
            j = next;
        }
        return 0;
    }
    int status = 0;
    for (int i = 1; i < argc; ++i) {
        ShJob *job = shJobFind(interp, argv[i]);
        if (!job) {
            status = 127;
            continue;
        }
        status = shWaitForJob(interp, job);
        if (job->state == SH_JOB_DONE) {
            shJobRemove(interp, job);
        }
    }
    return status;
}

static int builtinFg(ShInterp *interp, int argc, char **argv) {
    ShJob *job = shJobFind(interp, argc > 1 ? argv[1] : NULL);
    if (!job) {
        fprintf(stderr, "fg: no current job\n");
        return 1;
    }
    fprintf(stderr, "%s\n", job->command);
    if (interp->tty_fd >= 0) {
        tcsetpgrp(interp->tty_fd, job->pgid);
    }
    kill(-job->pgid, SIGCONT);
    job->state = SH_JOB_RUNNING;
    int status = shWaitForJob(interp, job);
    if (interp->tty_fd >= 0) {
        tcsetpgrp(interp->tty_fd, interp->tty_pgid);
    }
    if (job->state == SH_JOB_DONE) {
        shJobRemove(interp, job);
    }
    return status;
}

static int builtinBg(ShInterp *interp, int argc, char **argv) {
    ShJob *job = shJobFind(interp, argc > 1 ? argv[1] : NULL);
    if (!job) {
        fprintf(stderr, "bg: no current job\n");
        return 1;
    }
    kill(-job->pgid, SIGCONT);
    job->state = SH_JOB_RUNNING;
    shPrintJob(interp, job, false);
    return 0;
}

static int builtinKill(ShInterp *interp, int argc, char **argv) {
    int sig = SIGTERM;
    int i = 1;
    if (i < argc && argv[i][0] == '-' && argv[i][1]) {
        if (strcmp(argv[i], "-l") == 0) {
            for (size_t k = 1; k < sizeof(kSigNames) / sizeof(kSigNames[0]); ++k) {
                printf("%2d) SIG%s\n", kSigNames[k].sig, kSigNames[k].name);
            }
            return 0;
        }
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            sig = signalFromName(argv[i + 1]);
            i += 2;
        } else {
            sig = signalFromName(argv[i] + 1);
            i++;
        }
        if (sig < 0) {
            fprintf(stderr, "kill: bad signal\n");
            return 1;
        }
    }
    int status = 0;
    for (; i < argc; ++i) {
        pid_t target;
        if (argv[i][0] == '%') {
            ShJob *job = shJobFind(interp, argv[i]);
            if (!job) {
                fprintf(stderr, "kill: %s: no such job\n", argv[i]);
                status = 1;
                continue;
            }
            target = -job->pgid;
        } else {
            target = (pid_t)atol(argv[i]);
        }
        if (kill(target, sig) != 0) {
            fprintf(stderr, "kill: %s: %s\n", argv[i], strerror(errno));
            status = 1;
        }
    }
    return status;
}

/* ---- misc ---------------------------------------------------------------------------------- */

static int builtinUmask(ShInterp *interp, int argc, char **argv) {
    (void)interp;
    if (argc == 1) {
        mode_t cur = umask(0);
        umask(cur);
        printf("%04o\n", (unsigned)cur);
        return 0;
    }
    char *end = NULL;
    long mode = strtol(argv[1], &end, 8);
    if (!end || *end || mode < 0 || mode > 0777) {
        fprintf(stderr, "umask: %s: invalid mask\n", argv[1]);
        return 1;
    }
    umask((mode_t)mode);
    return 0;
}

static int builtinTimes(ShInterp *interp, int argc, char **argv) {
    (void)interp; (void)argc; (void)argv;
    struct tms t;
    clock_t ticks = times(&t);
    (void)ticks;
    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        hz = 100;
    }
    printf("%ldm%.3fs %ldm%.3fs\n%ldm%.3fs %ldm%.3fs\n",
           (long)(t.tms_utime / hz / 60), (double)(t.tms_utime % (hz * 60)) / hz,
           (long)(t.tms_stime / hz / 60), (double)(t.tms_stime % (hz * 60)) / hz,
           (long)(t.tms_cutime / hz / 60), (double)(t.tms_cutime % (hz * 60)) / hz,
           (long)(t.tms_cstime / hz / 60), (double)(t.tms_cstime % (hz * 60)) / hz);
    return 0;
}

static int builtinGetopts(ShInterp *interp, int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "getopts: usage: getopts optstring name [args]\n");
        return 2;
    }
    const char *optstring = argv[1];
    const char *varname = argv[2];
    bool silent = optstring[0] == ':';
    if (silent) {
        optstring++;
    }

    /* args to parse */
    char **args;
    int nargs;
    if (argc > 3) {
        args = argv + 3;
        nargs = argc - 3;
    } else {
        args = interp->params;
        nargs = interp->param_count;
    }

    const char *optind_s = shVarGet(interp, "OPTIND");
    int optind_v = optind_s ? atoi(optind_s) : 1;
    if (optind_v < 1) {
        optind_v = 1;
    }
    const char *optpos_s = shVarGet(interp, "_SH_OPTPOS");
    int optpos = optpos_s ? atoi(optpos_s) : 1;

    char numbuf[16];

    if (optind_v > nargs) {
        goto done;
    }
    {
        const char *cur = args[optind_v - 1];
        if (!cur || cur[0] != '-' || cur[1] == '\0') {
            goto done;
        }
        if (strcmp(cur, "--") == 0) {
            optind_v++;
            goto done;
        }
        if (optpos >= (int)strlen(cur)) {
            optind_v++;
            optpos = 1;
            if (optind_v > nargs) {
                goto done;
            }
            cur = args[optind_v - 1];
            if (!cur || cur[0] != '-' || cur[1] == '\0') {
                goto done;
            }
            if (strcmp(cur, "--") == 0) {
                optind_v++;
                goto done;
            }
        }
        char opt = cur[optpos];
        const char *found = opt == ':' ? NULL : strchr(optstring, opt);
        optpos++;

        char optbuf[2] = {opt, 0};
        if (!found) {
            shVarSet(interp, varname, "?", false);
            if (silent) {
                shVarSet(interp, "OPTARG", optbuf, false);
            } else {
                fprintf(stderr, "sh: illegal option -- %c\n", opt);
                shVarUnset(interp, "OPTARG");
            }
        } else if (found[1] == ':') {
            /* takes an argument */
            if (cur[optpos] != '\0') {
                shVarSet(interp, "OPTARG", cur + optpos, false);
                optind_v++;
                optpos = 1;
            } else if (optind_v < nargs) {
                shVarSet(interp, "OPTARG", args[optind_v], false);
                optind_v += 2;
                optpos = 1;
            } else {
                optind_v++;
                optpos = 1;
                if (silent) {
                    shVarSet(interp, varname, ":", false);
                    shVarSet(interp, "OPTARG", optbuf, false);
                } else {
                    shVarSet(interp, varname, "?", false);
                    fprintf(stderr, "sh: option requires an argument -- %c\n", opt);
                    shVarUnset(interp, "OPTARG");
                }
                goto save;
            }
            shVarSet(interp, varname, optbuf, false);
        } else {
            shVarSet(interp, varname, optbuf, false);
            shVarUnset(interp, "OPTARG");
            if (cur[optpos] == '\0') {
                optind_v++;
                optpos = 1;
            }
        }
    }
save:
    snprintf(numbuf, sizeof(numbuf), "%d", optind_v);
    shVarSet(interp, "OPTIND", numbuf, false);
    snprintf(numbuf, sizeof(numbuf), "%d", optpos);
    shVarSet(interp, "_SH_OPTPOS", numbuf, false);
    return 0;

done:
    snprintf(numbuf, sizeof(numbuf), "%d", optind_v);
    shVarSet(interp, "OPTIND", numbuf, false);
    shVarSet(interp, "_SH_OPTPOS", "1", false);
    shVarSet(interp, varname, "?", false);
    return 1;
}

static int builtinColon(ShInterp *interp, int argc, char **argv) {
    (void)interp; (void)argc; (void)argv;
    return 0;
}

static int builtinAliasStub(ShInterp *interp, int argc, char **argv) {
    (void)interp;
    if (argc > 1 && strcmp(argv[0], "alias") == 0) {
        /* Accepted for script compatibility; expansion is not performed. */
        return 0;
    }
    return 0;
}

/* ---- registry -------------------------------------------------------------------------------- */

static const ShBuiltin kBuiltins[] = {
    {":", builtinColon, true},
    {".", builtinDot, true},
    {"[", builtinTest, false},
    {"alias", builtinAliasStub, false},
    {"bg", builtinBg, false},
    {"break", builtinBreak, true},
    {"cd", builtinCd, false},
    {"command", builtinCommand, false},
    {"continue", builtinContinue, true},
    {"echo", builtinEcho, false},
    {"eval", builtinEval, true},
    {"exec", builtinExec, true},
    {"exit", builtinExit, true},
    {"export", builtinExport, true},
    {"false", builtinFalse, false},
    {"fg", builtinFg, false},
    {"getopts", builtinGetopts, false},
    {"hash", builtinHash, false},
    {"jobs", builtinJobs, false},
    {"kill", builtinKill, false},
    {"local", builtinLocal, false},
    {"printf", builtinPrintf, false},
    {"pwd", builtinPwd, false},
    {"read", builtinRead, false},
    {"readonly", builtinReadonly, true},
    {"return", builtinReturn, true},
    {"set", builtinSet, true},
    {"shift", builtinShift, true},
    {"source", builtinDot, false},
    {"test", builtinTest, false},
    {"times", builtinTimes, true},
    {"trap", builtinTrap, true},
    {"true", builtinTrue, false},
    {"type", builtinType, false},
    {"ulimit", builtinHash, false}, /* accepted no-op */
    {"umask", builtinUmask, false},
    {"unalias", builtinAliasStub, false},
    {"unset", builtinUnset, true},
    {"wait", builtinWait, false},
};

const ShBuiltin *shFindBuiltin(const char *name) {
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(kBuiltins) / sizeof(kBuiltins[0]); ++i) {
        if (strcmp(kBuiltins[i].name, name) == 0) {
            return &kBuiltins[i];
        }
    }
    return NULL;
}
