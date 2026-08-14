/* AST-walking executor: simple commands, pipelines, redirections, control
 * flow, functions, jobs, traps. */

#include "sh_interp.h"
#include "parser.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Applet dispatch hooks into smallclue proper (src/core.c; stubbed by
 * sh_applet_stubs.c for standalone unit testing). */
#include "../smallclue.h"

void shPushLocalScope(ShInterp *interp);
void shPopLocalScope(ShInterp *interp);

static ShInterp *gSignalInterp = NULL;

/* ---- signals --------------------------------------------------------------- */

static void shSignalHandler(int sig) {
    if (gSignalInterp && sig > 0 && sig < gSignalInterp->trap_count) {
        gSignalInterp->pending_signals[sig] = 1;
        if (sig == SIGINT) {
            gSignalInterp->got_sigint = 1;
        }
    }
}

void shInstallTrapHandler(ShInterp *interp, int sig);
void shInstallTrapHandler(ShInterp *interp, int sig) {
    gSignalInterp = interp;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shSignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(sig, &sa, NULL);
}

void shResetSignalsForChild(ShInterp *interp);
void shResetSignalsForChild(ShInterp *interp) {
    /* Traps are not inherited; ignored signals stay ignored. */
    for (int sig = 1; sig < interp->trap_count; ++sig) {
        if (interp->traps && interp->traps[sig] && interp->traps[sig][0] != '\0') {
            signal(sig, SIG_DFL);
        }
    }
    if (interp->interactive) {
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);
    }
}

void shRunPendingTraps(ShInterp *interp) {
    if (!interp->pending_signals) {
        return;
    }
    for (int sig = 1; sig < interp->trap_count; ++sig) {
        if (!interp->pending_signals[sig]) {
            continue;
        }
        interp->pending_signals[sig] = 0;
        if (interp->traps && interp->traps[sig] && interp->traps[sig][0] != '\0') {
            int saved = interp->last_status;
            shRunString(interp, interp->traps[sig], "trap");
            interp->last_status = saved;
        }
    }
}

void shRunExitTrap(ShInterp *interp) {
    if (interp->traps && interp->traps[0] && interp->traps[0][0] != '\0') {
        char *action = interp->traps[0];
        interp->traps[0] = NULL; /* avoid recursion */
        shRunString(interp, action, "exit trap");
        free(action);
    }
}

/* ---- jobs ------------------------------------------------------------------- */

static ShJob *jobAdd(ShInterp *interp, pid_t pgid, pid_t *pids, size_t count,
                     const char *command) {
    ShJob *job = (ShJob *)calloc(1, sizeof(ShJob));
    if (!job) {
        return NULL;
    }
    job->id = interp->next_job_id++;
    job->pgid = pgid;
    job->pids = (pid_t *)malloc(count * sizeof(pid_t));
    if (job->pids) {
        memcpy(job->pids, pids, count * sizeof(pid_t));
    }
    job->pid_count = count;
    job->pids_left = count;
    job->state = SH_JOB_RUNNING;
    job->command = command ? strdup(command) : strdup("");
    job->next = interp->jobs;
    interp->jobs = job;
    return job;
}

void shJobRemove(ShInterp *interp, ShJob *job) {
    ShJob **link = &interp->jobs;
    while (*link) {
        if (*link == job) {
            *link = job->next;
            free(job->pids);
            free(job->command);
            free(job);
            return;
        }
        link = &(*link)->next;
    }
    if (interp->jobs == NULL) {
        interp->next_job_id = 1;
    }
}

ShJob *shJobFind(ShInterp *interp, const char *spec) {
    if (!spec || !*spec) {
        return interp->jobs; /* most recent */
    }
    if (spec[0] == '%') {
        spec++;
    }
    if (!*spec || strcmp(spec, "%") == 0 || strcmp(spec, "+") == 0) {
        return interp->jobs;
    }
    if (strcmp(spec, "-") == 0) {
        return interp->jobs && interp->jobs->next ? interp->jobs->next : NULL;
    }
    char *end = NULL;
    long id = strtol(spec, &end, 10);
    if (end && *end == '\0') {
        for (ShJob *j = interp->jobs; j; j = j->next) {
            if (j->id == (int)id) {
                return j;
            }
        }
        /* fall through: maybe a raw pid */
        for (ShJob *j = interp->jobs; j; j = j->next) {
            for (size_t i = 0; i < j->pid_count; ++i) {
                if (j->pids[i] == (pid_t)id) {
                    return j;
                }
            }
        }
        return NULL;
    }
    /* %string: prefix match on command */
    for (ShJob *j = interp->jobs; j; j = j->next) {
        if (j->command && strncmp(j->command, spec, strlen(spec)) == 0) {
            return j;
        }
    }
    return NULL;
}

void shPrintJob(ShInterp *interp, ShJob *job, bool show_pids) {
    const char *state = job->state == SH_JOB_RUNNING   ? "Running"
                        : job->state == SH_JOB_STOPPED ? "Stopped"
                                                       : "Done";
    char current = (job == interp->jobs) ? '+' : (interp->jobs && job == interp->jobs->next ? '-' : ' ');
    if (show_pids) {
        printf("[%d]%c %ld %s    %s\n", job->id, current, (long)job->pgid, state, job->command);
    } else {
        printf("[%d]%c %s    %s\n", job->id, current, state, job->command);
    }
}

static void jobMarkPid(ShInterp *interp, pid_t pid, int status, bool stopped) {
    for (ShJob *j = interp->jobs; j; j = j->next) {
        for (size_t i = 0; i < j->pid_count; ++i) {
            if (j->pids[i] != pid) {
                continue;
            }
            if (stopped) {
                j->state = SH_JOB_STOPPED;
                return;
            }
            if (j->pids_left > 0) {
                j->pids_left--;
            }
            if (i == j->pid_count - 1) {
                j->last_status = status;
            }
            if (j->pids_left == 0) {
                j->state = SH_JOB_DONE;
            }
            return;
        }
    }
}

static int decodeWaitStatus(int wstatus) {
    if (WIFEXITED(wstatus)) {
        return WEXITSTATUS(wstatus);
    }
    if (WIFSIGNALED(wstatus)) {
        return 128 + WTERMSIG(wstatus);
    }
    if (WIFSTOPPED(wstatus)) {
        return 128 + WSTOPSIG(wstatus);
    }
    return 1;
}

void shReapJobs(ShInterp *interp, bool block_for_all) {
    for (;;) {
        int wstatus = 0;
        pid_t pid = waitpid(-1, &wstatus, block_for_all ? WUNTRACED : (WNOHANG | WUNTRACED));
        if (pid <= 0) {
            return;
        }
        jobMarkPid(interp, pid, decodeWaitStatus(wstatus), WIFSTOPPED(wstatus));
        if (block_for_all) {
            bool any_running = false;
            for (ShJob *j = interp->jobs; j; j = j->next) {
                if (j->state == SH_JOB_RUNNING) {
                    any_running = true;
                }
            }
            if (!any_running) {
                return;
            }
        }
    }
}

int shWaitForJob(ShInterp *interp, ShJob *job) {
    while (job->state == SH_JOB_RUNNING) {
        int wstatus = 0;
        pid_t pid = waitpid(-job->pgid, &wstatus, WUNTRACED);
        if (pid < 0) {
            if (errno == EINTR) {
                shRunPendingTraps(interp);
                if (interp->got_sigint) {
                    break;
                }
                continue;
            }
            if (errno == ECHILD) {
                job->state = SH_JOB_DONE;
                break;
            }
            break;
        }
        jobMarkPid(interp, pid, decodeWaitStatus(wstatus), WIFSTOPPED(wstatus));
    }
    return job->last_status;
}

/* Restore terminal to the shell after a foreground job. */
static void grabTerminal(ShInterp *interp) {
    if (interp->interactive && interp->opt_monitor && interp->tty_fd >= 0) {
        tcsetpgrp(interp->tty_fd, interp->tty_pgid);
    }
}

/* ---- redirections ------------------------------------------------------------ */

typedef struct SavedFd {
    int fd;        /* the fd that was changed */
    int saved;     /* dup'd copy of the original (-1 if fd was closed) */
    struct SavedFd *next;
} SavedFd;

static int saveFd(SavedFd **list, int fd) {
    SavedFd *entry = (SavedFd *)malloc(sizeof(SavedFd));
    if (!entry) {
        return -1;
    }
    entry->fd = fd;
    entry->saved = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    entry->next = *list;
    *list = entry;
    return 0;
}

static void restoreFds(SavedFd *list) {
    /* Builtins write through stdio: flush before the underlying fds change
     * back, or their output lands on the restored target. */
    if (list) {
        fflush(stdout);
        fflush(stderr);
    }
    while (list) {
        SavedFd *next = list->next;
        if (list->saved >= 0) {
            dup2(list->saved, list->fd);
            close(list->saved);
        } else {
            close(list->fd);
        }
        free(list);
        list = next;
    }
}

static void discardSavedFds(SavedFd *list) {
    while (list) {
        SavedFd *next = list->next;
        if (list->saved >= 0) {
            close(list->saved);
        }
        free(list);
        list = next;
    }
}

/* Write heredoc/here-string content to a readable fd (unlinked temp file). */
static int contentToFd(const char *content) {
    FILE *tmp = tmpfile();
    if (!tmp) {
        return -1;
    }
    if (content && *content) {
        fwrite(content, 1, strlen(content), tmp);
    }
    fflush(tmp);
    rewind(tmp);
    int fd = dup(fileno(tmp));
    fclose(tmp);
    if (fd >= 0) {
        lseek(fd, 0, SEEK_SET);
    }
    return fd;
}

/* Apply one redirection. If `saved` is non-NULL, original fds are saved for
 * later restore (in-process builtin execution). */
static int applyRedirection(ShInterp *interp, const ShellRedirection *redir, SavedFd **saved) {
    int io = -1;
    if (redir->io_number && *redir->io_number) {
        io = atoi(redir->io_number);
    }

    switch (redir->type) {
        case SHELL_REDIRECT_INPUT:
        case SHELL_REDIRECT_OUTPUT:
        case SHELL_REDIRECT_APPEND:
        case SHELL_REDIRECT_CLOBBER: {
            char *target = shExpandWordSingle(interp, redir->target);
            if (!target) {
                return -1;
            }
            int flags;
            int def_fd;
            if (redir->type == SHELL_REDIRECT_INPUT) {
                flags = O_RDONLY;
                def_fd = 0;
            } else if (redir->type == SHELL_REDIRECT_APPEND) {
                flags = O_WRONLY | O_CREAT | O_APPEND;
                def_fd = 1;
            } else {
                flags = O_WRONLY | O_CREAT | O_TRUNC;
                def_fd = 1;
                if (interp->opt_noclobber && redir->type == SHELL_REDIRECT_OUTPUT) {
                    flags = O_WRONLY | O_CREAT | O_EXCL;
                }
            }
            if (io < 0) {
                io = def_fd;
            }
            int fd = open(target, flags, 0666);
            if (fd < 0) {
                fprintf(stderr, "sh: %s: %s\n", target, strerror(errno));
                free(target);
                return -1;
            }
            free(target);
            if (saved) {
                saveFd(saved, io);
            }
            if (fd != io) {
                dup2(fd, io);
                close(fd);
            }
            return 0;
        }
        case SHELL_REDIRECT_HEREDOC: {
            const char *body = shellRedirectionGetHereDocument(redir);
            char *expanded = NULL;
            if (!shellRedirectionHereDocumentIsQuoted(redir)) {
                expanded = shExpandHereDocument(interp, body ? body : "");
                if (!expanded) {
                    return -1;
                }
                body = expanded;
            }
            int fd = contentToFd(body ? body : "");
            free(expanded);
            if (fd < 0) {
                return -1;
            }
            if (io < 0) {
                io = 0;
            }
            if (saved) {
                saveFd(saved, io);
            }
            if (fd != io) {
                dup2(fd, io);
                close(fd);
            }
            return 0;
        }
        case SHELL_REDIRECT_HERE_STRING: {
            const char *literal = shellRedirectionGetHereStringLiteral(redir);
            char *content = NULL;
            if (redir->target) {
                content = shExpandWordSingle(interp, redir->target);
            } else if (literal) {
                content = strdup(literal);
            }
            size_t clen = content ? strlen(content) : 0;
            char *with_nl = (char *)malloc(clen + 2);
            if (with_nl) {
                memcpy(with_nl, content ? content : "", clen);
                with_nl[clen] = '\n';
                with_nl[clen + 1] = '\0';
            }
            int fd = contentToFd(with_nl ? with_nl : "\n");
            free(content);
            free(with_nl);
            if (fd < 0) {
                return -1;
            }
            if (io < 0) {
                io = 0;
            }
            if (saved) {
                saveFd(saved, io);
            }
            if (fd != io) {
                dup2(fd, io);
                close(fd);
            }
            return 0;
        }
        case SHELL_REDIRECT_DUP_INPUT:
        case SHELL_REDIRECT_DUP_OUTPUT: {
            const char *target = shellRedirectionGetDupTarget(redir);
            char *expanded = NULL;
            if ((!target || !*target) && redir->target) {
                expanded = shExpandWordSingle(interp, redir->target);
                target = expanded;
            }
            if (io < 0) {
                io = (redir->type == SHELL_REDIRECT_DUP_INPUT) ? 0 : 1;
            }
            if (target && strcmp(target, "-") == 0) {
                if (saved) {
                    saveFd(saved, io);
                }
                close(io);
                free(expanded);
                return 0;
            }
            if (!target || !*target) {
                free(expanded);
                return -1;
            }
            int src = atoi(target);
            free(expanded);
            if (saved) {
                saveFd(saved, io);
            }
            if (dup2(src, io) < 0) {
                fprintf(stderr, "sh: %d: %s\n", src, strerror(errno));
                return -1;
            }
            return 0;
        }
        default:
            break;
    }
    return -1;
}

static int applyRedirections(ShInterp *interp, const ShellRedirectionArray *redirs,
                             SavedFd **saved) {
    if (!redirs) {
        return 0;
    }
    if (redirs->count > 0) {
        fflush(stdout);
        fflush(stderr);
    }
    for (size_t i = 0; i < redirs->count; ++i) {
        if (applyRedirection(interp, redirs->items[i], saved) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ---- command execution --------------------------------------------------------- */

static int runSimpleCommand(ShInterp *interp, const ShellCommand *command);
static int runPipeline(ShInterp *interp, const ShellPipeline *pipeline, const ShellCommand *owner);
static int runLogical(ShInterp *interp, const ShellLogicalList *logical);
static int runLoop(ShInterp *interp, const ShellCommand *command);
static int runConditional(ShInterp *interp, const ShellCommand *command);
static int runCase(ShInterp *interp, const ShellCommand *command);

static bool flowInterrupts(ShInterp *interp) {
    return interp->flow != SH_FLOW_NONE;
}

int shRunProgram(ShInterp *interp, const ShellProgram *program) {
    if (!program) {
        return interp->last_status;
    }
    int status = interp->last_status;
    for (size_t i = 0; i < program->commands.count; ++i) {
        status = shRunCommand(interp, program->commands.items[i]);
        if (flowInterrupts(interp)) {
            break;
        }
        shRunPendingTraps(interp);
        if (flowInterrupts(interp)) {
            break;
        }
    }
    return status;
}

/* Format a compact description of a command for job display. */
static char *describeCommand(const ShellCommand *command) {
    if (command->type == SHELL_COMMAND_SIMPLE && command->data.simple.words.count > 0) {
        size_t total = 0;
        const ShellWordArray *words = &command->data.simple.words;
        for (size_t i = 0; i < words->count; ++i) {
            total += strlen(words->items[i]->text ? words->items[i]->text : "") + 1;
        }
        char *out = (char *)malloc(total + 1);
        if (!out) {
            return strdup("job");
        }
        size_t pos = 0;
        for (size_t i = 0; i < words->count; ++i) {
            const char *t = words->items[i]->text ? words->items[i]->text : "";
            for (const char *p = t; *p; ++p) {
                if ((unsigned char)*p >= 0x04) {
                    out[pos++] = *p;
                }
            }
            if (i + 1 < words->count) {
                out[pos++] = ' ';
            }
        }
        out[pos] = '\0';
        return out;
    }
    return strdup("job");
}

/* Run a command in a forked child and register it as a background job. */
static int runBackground(ShInterp *interp, const ShellCommand *command) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sh: fork: %s\n", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        if (interp->opt_monitor) {
            setpgid(0, 0);
        }
        shResetSignalsForChild(interp);
        if (!interp->interactive) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
        }
        /* Background commands read from /dev/null unless redirected. */
        if (!interp->opt_monitor) {
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, 0);
                close(devnull);
            }
        }
        interp->interactive = false;
        interp->in_subshell = true;
        ShellCommand copy = *command;
        copy.exec.runs_in_background = false;
        int status = shRunCommand(interp, &copy);
        if (interp->flow == SH_FLOW_EXIT) {
            status = interp->exit_status;
        }
        fflush(NULL);
        _exit(status & 0xff);
    }
    if (interp->opt_monitor) {
        setpgid(pid, pid);
    }
    char *desc = describeCommand(command);
    ShJob *job = jobAdd(interp, pid, &pid, 1, desc);
    free(desc);
    interp->last_bg_pid = pid;
    if (interp->interactive && job) {
        fprintf(stderr, "[%d] %ld\n", job->id, (long)pid);
    }
    return 0;
}

int shRunCommand(ShInterp *interp, const ShellCommand *command) {
    if (!command) {
        return interp->last_status;
    }
    if (interp->opt_noexec) {
        return 0;
    }
    if (command->exec.runs_in_background) {
        int status = runBackground(interp, command);
        interp->last_status = status;
        return status;
    }

    interp->lineno = command->line;
    int status = 0;
    SavedFd *saved = NULL;
    bool applied_redirs = false;

    switch (command->type) {
        case SHELL_COMMAND_SIMPLE:
            status = runSimpleCommand(interp, command);
            break;
        case SHELL_COMMAND_ARITHMETIC: {
            long long value = 0;
            if (shArithEval(interp, command->data.arithmetic.expression, &value) != 0) {
                status = 2;
            } else {
                status = (value != 0) ? 0 : 1;
            }
            break;
        }
        case SHELL_COMMAND_PIPELINE:
            status = runPipeline(interp, command->data.pipeline, command);
            break;
        case SHELL_COMMAND_LOGICAL:
            status = runLogical(interp, command->data.logical);
            break;
        case SHELL_COMMAND_SUBSHELL: {
            if (applyRedirections(interp, &command->redirections, &saved) != 0) {
                restoreFds(saved);
                interp->last_status = 2; /* redirection failure */
                return 2;
            }
            applied_redirs = true;
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "sh: fork: %s\n", strerror(errno));
                status = 1;
                break;
            }
            if (pid == 0) {
                shResetSignalsForChild(interp);
                interp->in_subshell = true;
                int st = shRunProgram(interp, command->data.subshell.body);
                if (interp->flow == SH_FLOW_EXIT) {
                    st = interp->exit_status;
                }
                shRunExitTrap(interp);
                fflush(NULL);
                _exit(st & 0xff);
            }
            int wstatus = 0;
            while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) {
                shRunPendingTraps(interp);
            }
            status = decodeWaitStatus(wstatus);
            break;
        }
        case SHELL_COMMAND_BRACE_GROUP: {
            if (applyRedirections(interp, &command->data.brace_group.redirections, &saved) != 0 ||
                applyRedirections(interp, &command->redirections, &saved) != 0) {
                restoreFds(saved);
                interp->last_status = 2; /* redirection failure */
                return 2;
            }
            applied_redirs = true;
            status = shRunProgram(interp, command->data.brace_group.body);
            break;
        }
        case SHELL_COMMAND_LOOP:
            if (applyRedirections(interp, &command->data.loop->redirections, &saved) != 0 ||
                applyRedirections(interp, &command->redirections, &saved) != 0) {
                restoreFds(saved);
                interp->last_status = 2; /* redirection failure */
                return 2;
            }
            applied_redirs = true;
            status = runLoop(interp, command);
            break;
        case SHELL_COMMAND_CONDITIONAL:
            if (applyRedirections(interp, &command->redirections, &saved) != 0) {
                restoreFds(saved);
                interp->last_status = 2; /* redirection failure */
                return 2;
            }
            applied_redirs = true;
            status = runConditional(interp, command);
            break;
        case SHELL_COMMAND_CASE:
            if (applyRedirections(interp, &command->redirections, &saved) != 0) {
                restoreFds(saved);
                interp->last_status = 2; /* redirection failure */
                return 2;
            }
            applied_redirs = true;
            status = runCase(interp, command);
            break;
        case SHELL_COMMAND_FUNCTION: {
            const ShellFunction *fn = command->data.function;
            if (fn && fn->name) {
                status = shFuncDefine(interp, fn->name, fn->body);
            }
            break;
        }
        default:
            status = 0;
            break;
    }

    if (applied_redirs) {
        restoreFds(saved);
    }
    interp->last_status = status;

    /* set -e */
    if (interp->opt_errexit && status != 0 && interp->flow == SH_FLOW_NONE &&
        command->type != SHELL_COMMAND_LOGICAL && command->type != SHELL_COMMAND_CONDITIONAL &&
        command->type != SHELL_COMMAND_LOOP &&
        !(command->type == SHELL_COMMAND_PIPELINE && command->data.pipeline &&
          command->data.pipeline->negated)) {
        interp->flow = SH_FLOW_EXIT;
        interp->exit_status = status;
    }
    return status;
}

/* ---- logical lists / pipelines --------------------------------------------------- */

static int runLogical(ShInterp *interp, const ShellLogicalList *logical) {
    if (!logical || logical->count == 0) {
        return 0;
    }
    int status = 0;
    bool saved_errexit = interp->opt_errexit;
    for (size_t i = 0; i < logical->count; ++i) {
        if (i > 0) {
            /* connectors[i] is the connector *preceding* pipelines[i];
             * connectors[0] is a placeholder. */
            ShellLogicalConnector conn = logical->connectors[i];
            if (conn == SHELL_LOGICAL_AND && status != 0) {
                continue;
            }
            if (conn == SHELL_LOGICAL_OR && status == 0) {
                continue;
            }
        }
        /* errexit is suppressed for all but the last element */
        interp->opt_errexit = saved_errexit && (i == logical->count - 1);
        ShellCommand wrapper;
        memset(&wrapper, 0, sizeof(wrapper));
        wrapper.type = SHELL_COMMAND_PIPELINE;
        wrapper.data.pipeline = logical->pipelines[i];
        status = runPipeline(interp, logical->pipelines[i], NULL);
        interp->last_status = status;
        if (flowInterrupts(interp)) {
            break;
        }
    }
    interp->opt_errexit = saved_errexit;
    if (interp->opt_errexit && status != 0 && interp->flow == SH_FLOW_NONE) {
        interp->flow = SH_FLOW_EXIT;
        interp->exit_status = status;
    }
    return status;
}

static int runPipeline(ShInterp *interp, const ShellPipeline *pipeline, const ShellCommand *owner) {
    (void)owner;
    if (!pipeline || pipeline->command_count == 0) {
        return 0;
    }

    int status;
    if (pipeline->command_count == 1) {
        /* No pipe: run in-process to preserve variable assignments etc. */
        status = shRunCommand(interp, pipeline->commands[0]);
    } else {
        size_t n = pipeline->command_count;
        pid_t *pids = (pid_t *)calloc(n, sizeof(pid_t));
        int *statuses = (int *)calloc(n, sizeof(int));
        pid_t pgid = 0;
        int prev_read = -1;

        for (size_t i = 0; i < n; ++i) {
            int pipefd[2] = {-1, -1};
            if (i + 1 < n && pipe(pipefd) != 0) {
                fprintf(stderr, "sh: pipe: %s\n", strerror(errno));
                break;
            }
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "sh: fork: %s\n", strerror(errno));
                if (pipefd[0] >= 0) {
                    close(pipefd[0]);
                    close(pipefd[1]);
                }
                break;
            }
            if (pid == 0) {
                if (interp->opt_monitor && interp->interactive) {
                    setpgid(0, pgid);
                    if (i == 0 && interp->tty_fd >= 0) {
                        tcsetpgrp(interp->tty_fd, getpid());
                    }
                }
                shResetSignalsForChild(interp);
                interp->in_subshell = true;
                if (prev_read >= 0) {
                    dup2(prev_read, 0);
                    close(prev_read);
                }
                if (i + 1 < n) {
                    close(pipefd[0]);
                    dup2(pipefd[1], 1);
                    if (shellPipelineGetMergeStderr((ShellPipeline *)pipeline, i)) {
                        dup2(pipefd[1], 2);
                    }
                    close(pipefd[1]);
                }
                int st = shRunCommand(interp, pipeline->commands[i]);
                if (interp->flow == SH_FLOW_EXIT) {
                    st = interp->exit_status;
                }
                fflush(NULL);
                _exit(st & 0xff);
            }
            pids[i] = pid;
            if (i == 0) {
                pgid = pid;
            }
            if (interp->opt_monitor && interp->interactive) {
                setpgid(pid, pgid);
            }
            if (prev_read >= 0) {
                close(prev_read);
            }
            if (i + 1 < n) {
                close(pipefd[1]);
                prev_read = pipefd[0];
            }
        }
        if (prev_read >= 0) {
            close(prev_read);
        }

        for (size_t i = 0; i < n; ++i) {
            if (pids[i] <= 0) {
                statuses[i] = 1;
                continue;
            }
            int wstatus = 0;
            while (waitpid(pids[i], &wstatus, 0) < 0 && errno == EINTR) {
                shRunPendingTraps(interp);
            }
            statuses[i] = decodeWaitStatus(wstatus);
        }
        grabTerminal(interp);

        status = statuses[n - 1];
        if (interp->opt_pipefail) {
            for (size_t i = 0; i < n; ++i) {
                if (statuses[i] != 0) {
                    status = statuses[i];
                }
            }
        }
        free(pids);
        free(statuses);
    }

    if (pipeline->negated) {
        status = (status == 0) ? 1 : 0;
    }
    interp->last_status = status;
    return status;
}

/* ---- control flow ------------------------------------------------------------------ */

static int runLoop(ShInterp *interp, const ShellCommand *command) {
    const ShellLoop *loop = command->data.loop;
    int status = 0;
    interp->loop_depth++;

    if (loop->is_cstyle_for) {
        long long v = 0;
        if (loop->cstyle_init && *loop->cstyle_init) {
            shArithEval(interp, loop->cstyle_init, &v);
        }
        for (;;) {
            if (loop->cstyle_condition && *loop->cstyle_condition) {
                if (shArithEval(interp, loop->cstyle_condition, &v) != 0) {
                    status = 2;
                    break;
                }
                if (v == 0) {
                    break;
                }
            }
            status = shRunProgram(interp, loop->body);
            if (interp->flow == SH_FLOW_BREAK) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                }
                break;
            }
            if (interp->flow == SH_FLOW_CONTINUE) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                } else {
                    break;
                }
            } else if (flowInterrupts(interp)) {
                break;
            }
            if (loop->cstyle_update && *loop->cstyle_update) {
                shArithEval(interp, loop->cstyle_update, &v);
            }
        }
    } else if (loop->is_for) {
        char *varname = loop->for_variable ? shExpandWordSingle(interp, loop->for_variable) : NULL;
        ShFields values;
        shFieldsInit(&values);
        if (loop->for_values.count == 0) {
            /* `for x` iterates "$@" */
            for (int i = 0; i < interp->param_count; ++i) {
                shFieldsPush(&values, strdup(interp->params[i]));
            }
        } else {
            for (size_t i = 0; i < loop->for_values.count; ++i) {
                if (shExpandWord(interp, loop->for_values.items[i], &values) != 0) {
                    status = 1;
                    break;
                }
            }
        }
        for (size_t i = 0; varname && i < values.count; ++i) {
            shVarSet(interp, varname, values.items[i], false);
            status = shRunProgram(interp, loop->body);
            if (interp->flow == SH_FLOW_BREAK) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                }
                break;
            }
            if (interp->flow == SH_FLOW_CONTINUE) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                    continue;
                }
                break;
            }
            if (flowInterrupts(interp)) {
                break;
            }
        }
        shFieldsFree(&values);
        free(varname);
    } else {
        /* while / until */
        for (;;) {
            bool saved_errexit = interp->opt_errexit;
            interp->opt_errexit = false;
            int cond = shRunCommand(interp, loop->condition);
            interp->opt_errexit = saved_errexit;
            if (flowInterrupts(interp)) {
                break;
            }
            bool proceed = loop->is_until ? (cond != 0) : (cond == 0);
            if (!proceed) {
                break;
            }
            status = shRunProgram(interp, loop->body);
            if (interp->flow == SH_FLOW_BREAK) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                }
                break;
            }
            if (interp->flow == SH_FLOW_CONTINUE) {
                if (--interp->flow_count <= 0) {
                    interp->flow = SH_FLOW_NONE;
                    continue;
                }
                break;
            }
            if (flowInterrupts(interp)) {
                break;
            }
        }
    }

    interp->loop_depth--;
    return status;
}

static int runConditional(ShInterp *interp, const ShellCommand *command) {
    const ShellConditional *cond = command->data.conditional;
    bool saved_errexit = interp->opt_errexit;
    interp->opt_errexit = false;
    int test = shRunCommand(interp, cond->condition);
    interp->opt_errexit = saved_errexit;
    if (flowInterrupts(interp)) {
        return interp->last_status;
    }
    if (test == 0) {
        return shRunProgram(interp, cond->then_branch);
    }
    if (cond->else_branch) {
        return shRunProgram(interp, cond->else_branch);
    }
    return 0;
}

static int runCase(ShInterp *interp, const ShellCommand *command) {
    const ShellCase *cs = command->data.case_stmt;
    char *subject = shExpandWordSingle(interp, cs->subject);
    if (!subject) {
        return 1;
    }
    int status = 0;
    for (size_t i = 0; i < cs->clauses.count; ++i) {
        const ShellCaseClause *clause = cs->clauses.items[i];
        bool matched = false;
        for (size_t p = 0; p < clause->patterns.count && !matched; ++p) {
            char *pattern = shExpandPattern(interp, clause->patterns.items[p]);
            if (pattern && shPatternMatch(pattern, subject)) {
                matched = true;
            }
            free(pattern);
        }
        if (matched) {
            status = shRunProgram(interp, clause->body);
            break;
        }
    }
    free(subject);
    return status;
}

/* ---- simple commands ------------------------------------------------------------------ */

static void xtrace(ShInterp *interp, char **argv, size_t argc, char **assigns, size_t assign_count) {
    if (!interp->opt_xtrace) {
        return;
    }
    const char *ps4 = shVarGet(interp, "PS4");
    fprintf(stderr, "%s", ps4 ? ps4 : "+ ");
    bool first = true;
    for (size_t i = 0; i < assign_count; ++i) {
        fprintf(stderr, "%s%s", first ? "" : " ", assigns[i]);
        first = false;
    }
    for (size_t i = 0; i < argc; ++i) {
        fprintf(stderr, "%s%s", first ? "" : " ", argv[i]);
        first = false;
    }
    fprintf(stderr, "\n");
}

/* Search PATH for an executable. Returns malloc'd path or NULL. */
static char *pathSearch(ShInterp *interp, const char *name) {
    if (strchr(name, '/')) {
        return strdup(name);
    }
    const char *path = shVarGet(interp, "PATH");
    if (!path) {
        path = "/usr/bin:/bin";
    }
    const char *p = path;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t seg_len = colon ? (size_t)(colon - p) : strlen(p);
        char candidate[4096];
        if (seg_len == 0) {
            snprintf(candidate, sizeof(candidate), "./%s", name);
        } else {
            snprintf(candidate, sizeof(candidate), "%.*s/%s", (int)seg_len, p, name);
        }
        if (access(candidate, X_OK) == 0) {
            struct stat st;
            if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
                return strdup(candidate);
            }
        }
        if (!colon) {
            break;
        }
        p = colon + 1;
    }
    return NULL;
}

/* Exposed for `type`/`command -v`. */
char *shPathSearch(ShInterp *interp, const char *name);
char *shPathSearch(ShInterp *interp, const char *name) {
    return pathSearch(interp, name);
}

/* Execute an external command / applet in a forked child. */
static int runExternal(ShInterp *interp, char **argv, size_t argc,
                       const ShellRedirectionArray *redirs,
                       char **assign_names, char **assign_values, size_t assign_count) {
    const SmallclueApplet *applet =
        smallclueFindApplet(argv[0]);
    char *exec_path = NULL;
    if (!applet) {
        exec_path = pathSearch(interp, argv[0]);
        if (!exec_path) {
            fprintf(stderr, "sh: %s: not found\n", argv[0]);
            return 127;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sh: fork: %s\n", strerror(errno));
        free(exec_path);
        return 1;
    }
    if (pid == 0) {
        if (interp->opt_monitor && interp->interactive) {
            setpgid(0, 0);
            if (interp->tty_fd >= 0) {
                tcsetpgrp(interp->tty_fd, getpid());
            }
        }
        shResetSignalsForChild(interp);
        if (applyRedirections(interp, redirs, NULL) != 0) {
            _exit(1);
        }
        /* Command-scoped assignments become exported for the child. */
        for (size_t i = 0; i < assign_count; ++i) {
            shVarSet(interp, assign_names[i], assign_values[i], true);
            ShVar *v = NULL;
            (void)v;
            shVarExport(interp, assign_names[i], NULL);
        }
        char **envp = shBuildEnviron(interp);
        if (applet) {
            /* Run the applet in-process (we're already forked). */
            for (size_t i = 0; envp && envp[i]; ++i) {
                putenv(envp[i]);
            }
            int st = smallclueDispatchApplet(applet, (int)argc, argv);
            fflush(NULL);
            _exit(st & 0xff);
        }
        execve(exec_path, argv, envp ? envp : (char *[]){NULL});
        /* Script without shebang: run via ourselves. */
        if (errno == ENOEXEC) {
            size_t n = 0;
            while (argv[n]) {
                n++;
            }
            char **shargv = (char **)calloc(n + 3, sizeof(char *));
            if (shargv) {
                shargv[0] = (char *)"sh";
                shargv[1] = exec_path;
                for (size_t i = 1; i <= n; ++i) {
                    shargv[i + 1] = argv[i];
                }
                execv("/proc/self/exe", shargv);
                /* Fallback: interpret directly. */
                free(shargv);
            }
        }
        fprintf(stderr, "sh: %s: %s\n", argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (interp->opt_monitor && interp->interactive) {
        setpgid(pid, pid);
    }
    free(exec_path);
    int wstatus = 0;
    while (waitpid(pid, &wstatus, WUNTRACED) < 0 && errno == EINTR) {
        shRunPendingTraps(interp);
    }
    grabTerminal(interp);
    if (WIFSTOPPED(wstatus)) {
        /* Foreground job stopped: register it. */
        char *desc = strdup(argv[0]);
        ShJob *job = jobAdd(interp, pid, &pid, 1, desc);
        free(desc);
        if (job) {
            job->state = SH_JOB_STOPPED;
            fprintf(stderr, "\n");
            shPrintJob(interp, job, false);
        }
        return 128 + WSTOPSIG(wstatus);
    }
    return decodeWaitStatus(wstatus);
}

/* Call a shell function. */
static int callFunction(ShInterp *interp, ShFunction *fn, char **argv, size_t argc,
                        const ShellRedirectionArray *redirs) {
    SavedFd *saved = NULL;
    if (applyRedirections(interp, redirs, &saved) != 0) {
        restoreFds(saved);
        return 1;
    }

    /* Save positional parameters. */
    char **old_params = interp->params;
    int old_count = interp->param_count;

    interp->param_count = (int)(argc - 1);
    interp->params = (char **)calloc(argc > 1 ? argc - 1 : 1, sizeof(char *));
    for (size_t i = 1; i < argc; ++i) {
        interp->params[i - 1] = strdup(argv[i]);
    }

    shPushLocalScope(interp);
    interp->func_depth++;

    int status = shRunProgram(interp, fn->body);
    if (interp->flow == SH_FLOW_RETURN) {
        interp->flow = SH_FLOW_NONE;
        status = interp->exit_status;
    }

    interp->func_depth--;
    shPopLocalScope(interp);

    for (int i = 0; i < interp->param_count; ++i) {
        free(interp->params[i]);
    }
    free(interp->params);
    interp->params = old_params;
    interp->param_count = old_count;

    restoreFds(saved);
    return status;
}

static int runSimpleCommand(ShInterp *interp, const ShellCommand *command) {
    const ShellWordArray *words = &command->data.simple.words;
    interp->subst_ran = false;

    /* Partition into leading assignments and argv words. */
    ShFields argv_fields;
    shFieldsInit(&argv_fields);
    char **assign_names = NULL;
    char **assign_values = NULL;
    char **assign_display = NULL;
    size_t assign_count = 0;
    bool in_assignments = true;
    int status = 0;

    for (size_t i = 0; i < words->count; ++i) {
        const ShellWord *word = words->items[i];
        if (in_assignments && word->is_assignment) {
            /* Split name=value on the first unquoted '='. The lexer flags
             * the word; the marked text keeps the '=' literal. */
            const char *text = word->text ? word->text : "";
            const char *eq = strchr(text, '=');
            if (!eq) {
                in_assignments = false;
            } else {
                char *name = strndup(text, (size_t)(eq - text));
                /* Value: expand without splitting. Build a fake word. */
                ShellWord value_word = *word;
                value_word.text = (char *)(eq + 1);
                char *value = shExpandWordSingle(interp, &value_word);
                if (!value) {
                    free(name);
                    status = 1;
                    goto cleanup;
                }
                assign_names = (char **)realloc(assign_names, (assign_count + 1) * sizeof(char *));
                assign_values = (char **)realloc(assign_values, (assign_count + 1) * sizeof(char *));
                assign_display = (char **)realloc(assign_display, (assign_count + 1) * sizeof(char *));
                assign_names[assign_count] = name;
                assign_values[assign_count] = value;
                size_t dlen = strlen(name) + 1 + strlen(value) + 1;
                assign_display[assign_count] = (char *)malloc(dlen);
                if (assign_display[assign_count]) {
                    snprintf(assign_display[assign_count], dlen, "%s=%s", name, value);
                }
                assign_count++;
                continue;
            }
        }
        in_assignments = false;
        if (shExpandWord(interp, word, &argv_fields) != 0) {
            status = 1;
            goto cleanup;
        }
        if (flowInterrupts(interp)) {
            status = interp->last_status;
            goto cleanup;
        }
    }

    xtrace(interp, argv_fields.items, argv_fields.count, assign_display, assign_count);

    if (argv_fields.count == 0) {
        /* Assignments only: persist them. The command's status is that of
         * the last command substitution run during expansion (POSIX). */
        status = interp->subst_ran ? interp->subst_status : 0;
        for (size_t i = 0; i < assign_count; ++i) {
            if (shVarSet(interp, assign_names[i], assign_values[i], false) != 0) {
                status = 2; /* readonly-variable assignment: sh convention */
                /* Assignment errors (readonly) abort a non-interactive shell. */
                if (!interp->interactive) {
                    interp->flow = SH_FLOW_EXIT;
                    interp->exit_status = 2;
                }
            }
        }
        /* Redirections still apply (and are then dropped). */
        SavedFd *saved = NULL;
        if (applyRedirections(interp, &command->redirections, &saved) != 0) {
            status = 1;
        }
        restoreFds(saved);
        goto cleanup;
    }

    /* NULL-terminate argv. */
    shFieldsPush(&argv_fields, NULL);
    char **argv = argv_fields.items;
    size_t argc = argv_fields.count - 1;

    const char *name = argv[0];

    /* Resolution order: special builtins, functions, builtins, applets/PATH. */
    const ShBuiltin *builtin = shFindBuiltin(name);
    ShFunction *fn = (!builtin || !builtin->special) ? shFuncLookup(interp, name) : NULL;

    if (fn && (!builtin || !builtin->special)) {
        status = callFunction(interp, fn, argv, argc, &command->redirections);
    } else if (builtin) {
        /* `exec` redirections persist in the shell; everything else restores. */
        bool persist = strcmp(builtin->name, "exec") == 0;
        SavedFd *saved = NULL;
        if (applyRedirections(interp, &command->redirections, &saved) != 0) {
            restoreFds(saved);
            status = 2; /* redirection failure: sh convention, not a plain command failure */
            goto cleanup;
        }
        /* Assignments prefix a builtin: for special builtins they persist;
         * otherwise they're command-scoped (simplified: set + restore). */
        char **prev_values = NULL;
        bool *had_prev = NULL;
        if (assign_count > 0 && !builtin->special) {
            prev_values = (char **)calloc(assign_count, sizeof(char *));
            had_prev = (bool *)calloc(assign_count, sizeof(bool));
            for (size_t i = 0; i < assign_count; ++i) {
                const char *old = shVarGet(interp, assign_names[i]);
                had_prev[i] = old != NULL;
                prev_values[i] = old ? strdup(old) : NULL;
            }
        }
        for (size_t i = 0; i < assign_count; ++i) {
            shVarSet(interp, assign_names[i], assign_values[i], false);
        }
        status = builtin->fn(interp, (int)argc, argv);
        if (assign_count > 0 && !builtin->special) {
            for (size_t i = 0; i < assign_count; ++i) {
                if (had_prev[i]) {
                    shVarSet(interp, assign_names[i], prev_values[i], false);
                } else {
                    shVarUnset(interp, assign_names[i]);
                }
                free(prev_values[i]);
            }
            free(prev_values);
            free(had_prev);
        }
        if (persist) {
            discardSavedFds(saved);
        } else {
            restoreFds(saved);
        }
    } else {
        status = runExternal(interp, argv, argc, &command->redirections,
                             assign_names, assign_values, assign_count);
    }

cleanup:
    for (size_t i = 0; i < assign_count; ++i) {
        free(assign_names[i]);
        free(assign_values[i]);
        free(assign_display[i]);
    }
    free(assign_names);
    free(assign_values);
    free(assign_display);
    /* argv_fields may contain a trailing NULL sentinel; shFieldsFree handles it. */
    for (size_t i = 0; i < argv_fields.count; ++i) {
        free(argv_fields.items[i]);
    }
    free(argv_fields.items);
    return status;
}

/* ---- strings / substitution ---------------------------------------------------------- */

/* Run argv as a command, bypassing functions (for `command`). */
int shExecArgv(ShInterp *interp, int argc, char **argv);
int shExecArgv(ShInterp *interp, int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0]) {
        return 0;
    }
    const ShBuiltin *builtin = shFindBuiltin(argv[0]);
    if (builtin) {
        return builtin->fn(interp, argc, argv);
    }
    return runExternal(interp, argv, (size_t)argc, NULL, NULL, NULL, 0);
}

/* Replace the current process (for `exec cmd`). Only returns on failure. */
int shExecReplace(ShInterp *interp, char **argv);
int shExecReplace(ShInterp *interp, char **argv) {
    const SmallclueApplet *applet =
        smallclueFindApplet(argv[0]);
    char **envp = shBuildEnviron(interp);
    if (applet) {
        for (size_t i = 0; envp && envp[i]; ++i) {
            putenv(envp[i]);
        }
        int argc = 0;
        while (argv[argc]) {
            argc++;
        }
        int st = smallclueDispatchApplet(applet, argc, argv);
        fflush(NULL);
        _exit(st & 0xff);
    }
    char *path = pathSearch(interp, argv[0]);
    if (!path) {
        fprintf(stderr, "sh: exec: %s: not found\n", argv[0]);
        shFreeEnviron(envp);
        return 127;
    }
    execve(path, argv, envp ? envp : (char *[]){NULL});
    fprintf(stderr, "sh: exec: %s: %s\n", argv[0], strerror(errno));
    free(path);
    shFreeEnviron(envp);
    return errno == ENOENT ? 127 : 126;
}

int shRunString(ShInterp *interp, const char *source, const char *origin) {
    if (!source) {
        return 0;
    }
    if (interp->depth > 100) {
        fprintf(stderr, "sh: %s: recursion limit exceeded\n", origin ? origin : "eval");
        return 2;
    }
    ShellParser parser;
    memset(&parser, 0, sizeof(parser));
    ShellProgram *program = shellParseString(source, &parser);
    if (!program || parser.had_error) {
        if (program) {
            shellFreeProgram(program);
        }
        shellParserFree(&parser);
        fprintf(stderr, "sh: %s: syntax error\n", origin ? origin : "input");
        return 2;
    }
    interp->depth++;
    int status = shRunProgram(interp, program);
    interp->depth--;
    shellFreeProgram(program);
    shellParserFree(&parser);
    return status;
}

int shCommandSubstitution(ShInterp *interp, const char *source, char **out) {
    if (out) {
        *out = NULL;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        close(pipefd[1]);
        shResetSignalsForChild(interp);
        interp->in_subshell = true;
        interp->interactive = false;
        int status = shRunString(interp, source, "command substitution");
        if (interp->flow == SH_FLOW_EXIT) {
            status = interp->exit_status;
        }
        fflush(NULL);
        _exit(status & 0xff);
    }
    close(pipefd[1]);

    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) {
                break;
            }
            buf = tmp;
        }
        ssize_t r = read(pipefd[0], buf + len, 4096);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        len += (size_t)r;
    }
    close(pipefd[0]);
    if (buf) {
        buf[len] = '\0';
    }

    int wstatus = 0;
    while (waitpid(pid, &wstatus, 0) < 0 && errno == EINTR) {
    }
    if (out) {
        *out = buf ? buf : strdup("");
    } else {
        free(buf);
    }
    return decodeWaitStatus(wstatus);
}
