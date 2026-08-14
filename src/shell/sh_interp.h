#ifndef SMALLCLUE_SH_INTERP_H
#define SMALLCLUE_SH_INTERP_H

/* smallclue's native POSIX shell interpreter.
 *
 * The lexer/parser/AST in this directory are vendored from exsh; where exsh
 * compiles the AST to PSCAL bytecode and runs it on the PSCAL VM, this
 * interpreter walks the AST directly so standalone smallclue builds get a
 * BusyBox-ash-class /bin/sh with no VM dependency. */

#include "ast.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- variables ---------------------------------------------------------- */

typedef struct ShVar {
    char *name;
    char *value;            /* NULL means "unset but flagged" (e.g. export FOO) */
    bool exported;
    bool read_only;
    struct ShVar *next;
} ShVar;

/* One frame of `local` bookkeeping: how to restore a variable when the
 * enclosing function returns. */
typedef struct ShLocalSave {
    char *name;
    char *saved_value;      /* NULL = was unset */
    bool had_var;
    bool was_exported;
    bool was_read_only;
    struct ShLocalSave *next;
} ShLocalSave;

typedef struct ShFuncFrame {
    ShLocalSave *locals;
    struct ShFuncFrame *next;
} ShFuncFrame;

/* ---- functions ---------------------------------------------------------- */

typedef struct ShFunction {
    char *name;
    ShellProgram *body;     /* owned; deep-copied from the defining AST */
    struct ShFunction *next;
} ShFunction;

/* ---- jobs --------------------------------------------------------------- */

typedef enum {
    SH_JOB_RUNNING,
    SH_JOB_STOPPED,
    SH_JOB_DONE
} ShJobState;

typedef struct ShJob {
    int id;
    pid_t pgid;
    pid_t *pids;
    size_t pid_count;
    size_t pids_left;       /* not yet reaped */
    int last_status;        /* exit status of the last process in the job */
    ShJobState state;
    char *command;          /* display string */
    bool notified;
    struct ShJob *next;
} ShJob;

/* ---- control flow ------------------------------------------------------- */

typedef enum {
    SH_FLOW_NONE = 0,
    SH_FLOW_BREAK,
    SH_FLOW_CONTINUE,
    SH_FLOW_RETURN,
    SH_FLOW_EXIT
} ShFlow;

/* ---- interpreter state -------------------------------------------------- */

typedef struct ShInterp {
    ShVar *vars;
    ShFunction *functions;
    ShFuncFrame *func_frames;   /* non-NULL while executing a function */

    /* positional parameters ($0 is arg0, params[0] is $1) */
    char *arg0;
    char **params;
    int param_count;

    int last_status;            /* $? */
    int subst_status;           /* status of the last $(...) this command */
    bool subst_ran;             /* a $(...) ran during the current expansion */
    pid_t last_bg_pid;          /* $! */
    pid_t shell_pid;            /* $$ (never changes in subshells, per POSIX) */

    /* set(1) options */
    bool opt_errexit;           /* -e */
    bool opt_nounset;           /* -u */
    bool opt_xtrace;            /* -x */
    bool opt_noglob;            /* -f */
    bool opt_noexec;            /* -n */
    bool opt_noclobber;         /* -C */
    bool opt_allexport;         /* -a */
    bool opt_verbose;           /* -v */
    bool opt_pipefail;          /* -o pipefail */
    bool opt_monitor;           /* -m: job control */
    bool interactive;

    ShFlow flow;
    int flow_count;             /* levels for break/continue */
    int exit_status;            /* status for SH_FLOW_EXIT / return */

    int loop_depth;
    int func_depth;

    /* traps: index 0 = EXIT, 1..NSIG-1 = signals. NULL = default,
     * "" = ignore, anything else = command string. */
    char **traps;
    int trap_count;
    volatile sig_atomic_t *pending_signals;
    volatile sig_atomic_t got_sigint;

    ShJob *jobs;
    int next_job_id;
    pid_t tty_pgid;             /* our pgid when interactive */
    int tty_fd;

    bool in_subshell;
    int depth;                  /* eval/source recursion guard */

    const char *script_name;    /* for error messages */
    int lineno;
} ShInterp;

/* ---- expansion results --------------------------------------------------- */

typedef struct ShFields {
    char **items;
    size_t count;
    size_t capacity;
} ShFields;

void shFieldsInit(ShFields *fields);
void shFieldsPush(ShFields *fields, char *item); /* takes ownership */
void shFieldsFree(ShFields *fields);

/* ---- API ----------------------------------------------------------------- */

/* interp lifecycle */
ShInterp *shInterpCreate(void);
void shInterpDestroy(ShInterp *interp);

/* variables */
const char *shVarGet(ShInterp *interp, const char *name);
int shVarSet(ShInterp *interp, const char *name, const char *value, bool exported);
int shVarUnset(ShInterp *interp, const char *name);
void shVarExport(ShInterp *interp, const char *name, const char *value_or_null);
void shVarMakeReadOnly(ShInterp *interp, const char *name, const char *value_or_null);
char **shBuildEnviron(ShInterp *interp);        /* NULL-terminated, caller frees deep */
void shFreeEnviron(char **envp);
void shVarMarkLocal(ShInterp *interp, const char *name); /* register in current frame */

/* functions */
ShFunction *shFuncLookup(ShInterp *interp, const char *name);
int shFuncDefine(ShInterp *interp, const char *name, const ShellProgram *body);
int shFuncUndefine(ShInterp *interp, const char *name);

/* expansion (sh_expand.c) */
/* Expand a word into zero or more fields (tilde/param/cmdsubst/arith,
 * field splitting, globbing, quote removal). */
int shExpandWord(ShInterp *interp, const ShellWord *word, ShFields *out);
/* Expansion without field splitting or globbing (redirect targets, case
 * subjects, assignment values). Always yields exactly one string. */
char *shExpandWordSingle(ShInterp *interp, const ShellWord *word);
/* Expand a raw sh fragment (heredoc bodies with expansion enabled). */
char *shExpandHereDocument(ShInterp *interp, const char *body);
/* Pattern-match helpers shared by case / ${var#pat} / globbing. */
char *shExpandPattern(ShInterp *interp, const ShellWord *word); /* fnmatch-ready */
bool shPatternMatch(const char *pattern, const char *string);

/* arithmetic (sh_arith.c) */
int shArithEval(ShInterp *interp, const char *expr, long long *result);

/* execution (sh_exec.c) */
int shRunProgram(ShInterp *interp, const ShellProgram *program);
int shRunCommand(ShInterp *interp, const ShellCommand *command);
int shRunString(ShInterp *interp, const char *source, const char *origin);
/* Run `source` in a forked subshell with stdout captured into *out. */
int shCommandSubstitution(ShInterp *interp, const char *source, char **out);
void shReapJobs(ShInterp *interp, bool block_for_all);
void shRunPendingTraps(ShInterp *interp);
void shRunExitTrap(ShInterp *interp);
int shWaitForJob(ShInterp *interp, ShJob *job);
ShJob *shJobFind(ShInterp *interp, const char *spec);
void shJobRemove(ShInterp *interp, ShJob *job);
void shPrintJob(ShInterp *interp, ShJob *job, bool show_pids);

/* builtins (sh_builtins.c) */
typedef int (*ShBuiltinFn)(ShInterp *interp, int argc, char **argv);
typedef struct ShBuiltin {
    const char *name;
    ShBuiltinFn fn;
    bool special;   /* POSIX special builtin: assignment persistence, errors fatal */
} ShBuiltin;
const ShBuiltin *shFindBuiltin(const char *name);

/* line editing (sh_lineedit.c): returns malloc'd line without trailing
 * newline, or NULL on EOF. Falls back to plain reads on non-ttys. */
char *shReadLineInteractive(ShInterp *interp, const char *prompt);
void shLineEditAddHistory(const char *line);
void shLineEditLoadHistory(void);
void shLineEditSaveHistory(void);

/* entry point (sh_main.c) */
int shMain(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* SMALLCLUE_SH_INTERP_H */
