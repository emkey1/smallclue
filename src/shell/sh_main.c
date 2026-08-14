/* Shell entry point: argument handling, script/-c/stdin modes, interactive
 * REPL with multi-line continuation. */

#include "sh_interp.h"
#include "parser.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void shInstallTrapHandler(ShInterp *interp, int sig);

static char *readWholeFile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Is `source` an incomplete construct that needs more input (PS2)?
 * Heuristic: parse and look for the specific unterminated-construct error. */
static bool parseIsIncomplete(const char *source) {
    /* Cheap structural check: unterminated quotes, heredocs, or compound
     * keywords without their closers. Parse and inspect had_error along
     * with whether the source ends mid-construct. */
    size_t len = strlen(source);
    bool in_s = false, in_d = false;
    int paren = 0, brace = 0;
    int compound = 0; /* if/while/for/until/case nesting */
    bool heredoc = false;

    /* crude token scan */
    for (size_t i = 0; i < len; ++i) {
        char c = source[i];
        if (in_s) {
            if (c == '\'') in_s = false;
            continue;
        }
        if (c == '\\') {
            i++;
            continue;
        }
        if (in_d) {
            if (c == '"') in_d = false;
            continue;
        }
        if (c == '\'') { in_s = true; continue; }
        if (c == '"') { in_d = true; continue; }
        if (c == '#') {
            while (i < len && source[i] != '\n') i++;
            continue;
        }
        if (c == '(') paren++;
        else if (c == ')') paren--;
        else if (c == '{' && (i == 0 || strchr(" \t\n;|&", source[i - 1]))) brace++;
        else if (c == '}' && (i == 0 || strchr(" \t\n;", source[i - 1]))) brace--;
        else if (c == '<' && i + 1 < len && source[i + 1] == '<') {
            heredoc = true;
            i++;
        } else if (isalpha((unsigned char)c) &&
                   (i == 0 || strchr(" \t\n;|&({", source[i - 1]))) {
            size_t j = i;
            while (j < len && isalpha((unsigned char)source[j])) j++;
            size_t wl = j - i;
            const char *w = source + i;
            bool at_end_ok = (j >= len) || strchr(" \t\n;|&)", source[j]);
            if (at_end_ok) {
                if ((wl == 2 && strncmp(w, "if", 2) == 0) ||
                    (wl == 5 && strncmp(w, "while", 5) == 0) ||
                    (wl == 5 && strncmp(w, "until", 5) == 0) ||
                    (wl == 3 && strncmp(w, "for", 3) == 0) ||
                    (wl == 4 && strncmp(w, "case", 4) == 0)) {
                    compound++;
                } else if ((wl == 2 && strncmp(w, "fi", 2) == 0) ||
                           (wl == 4 && strncmp(w, "done", 4) == 0) ||
                           (wl == 4 && strncmp(w, "esac", 4) == 0)) {
                    compound--;
                }
            }
            i = j - 1;
        }
    }
    if (in_s || in_d || paren > 0 || brace > 0 || compound > 0) {
        return true;
    }
    if (len > 0) {
        /* trailing backslash-newline or trailing | && || */
        size_t e = len;
        while (e > 0 && (source[e - 1] == ' ' || source[e - 1] == '\t' || source[e - 1] == '\n')) {
            e--;
        }
        if (e > 0 && source[e - 1] == '\\') {
            return true;
        }
        if (e > 0 && (source[e - 1] == '|' || source[e - 1] == '&')) {
            /* `foo |`, `foo &&`, but plain `foo &` is complete */
            if (source[e - 1] == '|' || (e > 1 && source[e - 2] == '&')) {
                return true;
            }
        }
    }
    if (heredoc) {
        /* If a heredoc delimiter opened, require the body to have terminated:
         * cheap approach: try parsing; unterminated heredocs error out. */
        ShellParser parser;
        memset(&parser, 0, sizeof(parser));
        ShellProgram *program = shellParseString(source, &parser);
        bool bad = parser.had_error;
        if (program) {
            shellFreeProgram(program);
        }
        shellParserFree(&parser);
        return bad;
    }
    return false;
}

static void setShellName(ShInterp *interp, const char *arg0) {
    free(interp->arg0);
    interp->arg0 = strdup(arg0);
    interp->script_name = interp->arg0;
}

/* Source a startup file in the current shell, ignoring missing files. */
static void sourceIfReadable(ShInterp *interp, const char *path) {
    if (!path || !*path || access(path, R_OK) != 0) {
        return;
    }
    char *source = readWholeFile(path);
    if (source) {
        shRunString(interp, source, path);
        free(source);
        interp->flow = SH_FLOW_NONE;
    }
}

/* Login shells read /etc/profile and ~/.profile; interactive shells then
 * read the file named by $ENV (after expansion), as BusyBox ash does. */
static void runStartupFiles(ShInterp *interp, bool login_shell) {
    if (login_shell) {
        sourceIfReadable(interp, "/etc/profile");
        const char *home = shVarGet(interp, "HOME");
        if (home && *home) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/.profile", home);
            sourceIfReadable(interp, path);
        }
    }
    const char *env = shVarGet(interp, "ENV");
    if (env && *env) {
        char *expanded = shExpandHereDocument(interp, env);
        sourceIfReadable(interp, expanded ? expanded : env);
        free(expanded);
    }
}

static int runInteractive(ShInterp *interp) {
    interp->interactive = true;
    interp->tty_fd = STDIN_FILENO;
    interp->tty_pgid = getpgrp();

    if (interp->opt_monitor) {
        /* Take the terminal. */
        while (tcgetpgrp(interp->tty_fd) != (interp->tty_pgid = getpgrp())) {
            kill(-interp->tty_pgid, SIGTTIN);
        }
        signal(SIGTTIN, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);
        setpgid(0, 0);
        interp->tty_pgid = getpgrp();
        tcsetpgrp(interp->tty_fd, interp->tty_pgid);
    }
    signal(SIGQUIT, SIG_IGN);
    shInstallTrapHandler(interp, SIGINT);

    shLineEditLoadHistory();

    char *pending = NULL;
    for (;;) {
        if (interp->flow == SH_FLOW_EXIT) {
            break;
        }
        interp->flow = SH_FLOW_NONE;
        interp->got_sigint = 0;

        /* Notify about finished background jobs. */
        shReapJobs(interp, false);
        ShJob *j = interp->jobs;
        while (j) {
            ShJob *next = j->next;
            if (j->state == SH_JOB_DONE && !j->notified) {
                shPrintJob(interp, j, false);
                shJobRemove(interp, j);
            }
            j = next;
        }

        const char *ps = pending ? shVarGet(interp, "PS2") : shVarGet(interp, "PS1");
        char *line = shReadLineInteractive(interp, ps ? ps : (pending ? "> " : "$ "));
        if (!line) {
            if (interp->got_sigint) {
                free(pending);
                pending = NULL;
                interp->got_sigint = 0;
                continue;
            }
            /* EOF */
            if (pending) {
                free(pending);
                pending = NULL;
                continue;
            }
            break;
        }

        char *source;
        if (pending) {
            size_t total = strlen(pending) + 1 + strlen(line) + 1;
            source = (char *)malloc(total);
            snprintf(source, total, "%s\n%s", pending, line);
            free(pending);
            pending = NULL;
        } else {
            source = strdup(line);
        }
        free(line);

        /* Skip blank lines. */
        bool blank = true;
        for (const char *p = source; *p; ++p) {
            if (*p != ' ' && *p != '\t' && *p != '\n') {
                blank = false;
                break;
            }
        }
        if (blank) {
            free(source);
            continue;
        }

        if (parseIsIncomplete(source)) {
            pending = source;
            continue;
        }

        shLineEditAddHistory(source);
        if (interp->opt_verbose) {
            fprintf(stderr, "%s\n", source);
        }
        shRunString(interp, source, "stdin");
        free(source);
        shRunPendingTraps(interp);
    }
    free(pending);

    shLineEditSaveHistory();
    return interp->flow == SH_FLOW_EXIT ? interp->exit_status : interp->last_status;
}

static int runStdinNonInteractive(ShInterp *interp) {
    /* Read all of stdin and execute. */
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return 1;
    }
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) {
                free(buf);
                return 1;
            }
            buf = tmp;
        }
        ssize_t r = read(0, buf + len, 4096);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        len += (size_t)r;
    }
    buf[len] = '\0';
    int status = shRunString(interp, buf, "stdin");
    free(buf);
    if (interp->flow == SH_FLOW_EXIT) {
        status = interp->exit_status;
    }
    return status;
}

int shMain(int argc, char **argv) {
    ShInterp *interp = shInterpCreate();
    if (!interp) {
        fprintf(stderr, "sh: out of memory\n");
        return 1;
    }

    const char *command_string = NULL;
    const char *script_path = NULL;
    bool read_stdin = false;
    bool force_interactive = false;
    bool login_shell = argv && argv[0] && argv[0][0] == '-';

    int i = 1;
    for (; i < argc; ++i) {
        const char *a = argv[i];
        if (strcmp(a, "-c") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "sh: -c requires an argument\n");
                shInterpDestroy(interp);
                return 2;
            }
            command_string = argv[++i];
            i++;
            break;
        }
        if (strcmp(a, "-s") == 0) {
            read_stdin = true;
            continue;
        }
        if (strcmp(a, "-i") == 0) {
            force_interactive = true;
            continue;
        }
        if (strcmp(a, "--") == 0) {
            i++;
            break;
        }
        if (a[0] == '-' && a[1]) {
            /* set-style options: -e, -x, -u, ... */
            bool ok = true;
            for (const char *p = a + 1; *p; ++p) {
                switch (*p) {
                    case 'e': interp->opt_errexit = true; break;
                    case 'u': interp->opt_nounset = true; break;
                    case 'x': interp->opt_xtrace = true; break;
                    case 'f': interp->opt_noglob = true; break;
                    case 'n': interp->opt_noexec = true; break;
                    case 'C': interp->opt_noclobber = true; break;
                    case 'a': interp->opt_allexport = true; break;
                    case 'v': interp->opt_verbose = true; break;
                    case 'm': interp->opt_monitor = true; break;
                    case 'l': login_shell = true; break;
                    default: ok = false; break;
                }
                if (!ok) {
                    break;
                }
            }
            if (!ok) {
                fprintf(stderr, "sh: %s: bad option\n", a);
                shInterpDestroy(interp);
                return 2;
            }
            continue;
        }
        break;
    }

    int status = 0;
    if (command_string) {
        /* sh -c 'cmd' [name [args...]] */
        if (i < argc) {
            setShellName(interp, argv[i]);
            i++;
        } else {
            setShellName(interp, argv[0]);
        }
        if (i < argc) {
            interp->param_count = argc - i;
            interp->params = (char **)calloc((size_t)(argc - i), sizeof(char *));
            for (int p = i; p < argc; ++p) {
                interp->params[p - i] = strdup(argv[p]);
            }
        }
        status = shRunString(interp, command_string, "-c");
        if (interp->flow == SH_FLOW_EXIT) {
            status = interp->exit_status;
        }
    } else if (i < argc && !read_stdin) {
        /* script file */
        script_path = argv[i];
        setShellName(interp, script_path);
        if (i + 1 < argc) {
            interp->param_count = argc - i - 1;
            interp->params = (char **)calloc((size_t)(argc - i - 1), sizeof(char *));
            for (int p = i + 1; p < argc; ++p) {
                interp->params[p - i - 1] = strdup(argv[p]);
            }
        }
        char *source = readWholeFile(script_path);
        if (!source) {
            fprintf(stderr, "sh: %s: %s\n", script_path, strerror(errno));
            shInterpDestroy(interp);
            return 127;
        }
        /* Skip a shebang line. */
        char *body = source;
        if (body[0] == '#' && body[1] == '!') {
            char *nl = strchr(body, '\n');
            body = nl ? nl + 1 : body + strlen(body);
        }
        status = shRunString(interp, body, script_path);
        free(source);
        if (interp->flow == SH_FLOW_EXIT) {
            status = interp->exit_status;
        }
    } else {
        setShellName(interp, argv[0]);
        if (i < argc) {
            interp->param_count = argc - i;
            interp->params = (char **)calloc((size_t)(argc - i), sizeof(char *));
            for (int p = i; p < argc; ++p) {
                interp->params[p - i] = strdup(argv[p]);
            }
        }
        if (force_interactive || isatty(STDIN_FILENO)) {
            interp->opt_monitor = true;
            interp->interactive = true;
            runStartupFiles(interp, login_shell);
            status = runInteractive(interp);
        } else {
            status = runStdinNonInteractive(interp);
        }
    }

    shRunExitTrap(interp);
    fflush(NULL);
    shInterpDestroy(interp);
    return status & 0xff;
}
