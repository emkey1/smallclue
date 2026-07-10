/* Interpreter state: variables, scopes, functions, fields. */

#include "sh_interp.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

void shFieldsInit(ShFields *fields) {
    fields->items = NULL;
    fields->count = 0;
    fields->capacity = 0;
}

void shFieldsPush(ShFields *fields, char *item) {
    if (fields->count + 1 > fields->capacity) {
        size_t cap = fields->capacity ? fields->capacity * 2 : 8;
        char **tmp = (char **)realloc(fields->items, cap * sizeof(char *));
        if (!tmp) {
            return;
        }
        fields->items = tmp;
        fields->capacity = cap;
    }
    fields->items[fields->count++] = item;
}

void shFieldsFree(ShFields *fields) {
    for (size_t i = 0; i < fields->count; ++i) {
        free(fields->items[i]);
    }
    free(fields->items);
    shFieldsInit(fields);
}

/* ---- variables ---------------------------------------------------------- */

static ShVar *shVarFind(ShInterp *interp, const char *name) {
    for (ShVar *v = interp->vars; v; v = v->next) {
        if (strcmp(v->name, name) == 0) {
            return v;
        }
    }
    return NULL;
}

const char *shVarGet(ShInterp *interp, const char *name) {
    ShVar *v = shVarFind(interp, name);
    return v ? v->value : NULL;
}

int shVarSet(ShInterp *interp, const char *name, const char *value, bool exported) {
    ShVar *v = shVarFind(interp, name);
    if (v) {
        if (v->read_only) {
            fprintf(stderr, "sh: %s: readonly variable\n", name);
            return 1;
        }
        char *copy = value ? strdup(value) : NULL;
        free(v->value);
        v->value = copy;
        if (exported || interp->opt_allexport) {
            v->exported = true;
        }
        return 0;
    }
    v = (ShVar *)calloc(1, sizeof(ShVar));
    if (!v) {
        return 1;
    }
    v->name = strdup(name);
    v->value = value ? strdup(value) : NULL;
    v->exported = exported || interp->opt_allexport;
    v->next = interp->vars;
    interp->vars = v;
    return 0;
}

int shVarUnset(ShInterp *interp, const char *name) {
    ShVar **link = &interp->vars;
    while (*link) {
        ShVar *v = *link;
        if (strcmp(v->name, name) == 0) {
            if (v->read_only) {
                fprintf(stderr, "sh: %s: readonly variable\n", name);
                return 1;
            }
            *link = v->next;
            free(v->name);
            free(v->value);
            free(v);
            return 0;
        }
        link = &v->next;
    }
    return 0;
}

void shVarExport(ShInterp *interp, const char *name, const char *value_or_null) {
    ShVar *v = shVarFind(interp, name);
    if (!v) {
        shVarSet(interp, name, value_or_null, true);
        v = shVarFind(interp, name);
        if (v && !value_or_null) {
            free(v->value);
            v->value = NULL; /* exported-but-unset placeholder */
        }
        return;
    }
    if (value_or_null) {
        if (v->read_only) {
            fprintf(stderr, "sh: %s: readonly variable\n", name);
            return;
        }
        char *copy = strdup(value_or_null);
        free(v->value);
        v->value = copy;
    }
    v->exported = true;
}

void shVarMakeReadOnly(ShInterp *interp, const char *name, const char *value_or_null) {
    ShVar *v = shVarFind(interp, name);
    if (!v) {
        shVarSet(interp, name, value_or_null ? value_or_null : "", false);
        v = shVarFind(interp, name);
    } else if (value_or_null && !v->read_only) {
        char *copy = strdup(value_or_null);
        free(v->value);
        v->value = copy;
    }
    if (v) {
        v->read_only = true;
    }
}

char **shBuildEnviron(ShInterp *interp) {
    size_t count = 0;
    for (ShVar *v = interp->vars; v; v = v->next) {
        if (v->exported && v->value) {
            count++;
        }
    }
    char **envp = (char **)calloc(count + 1, sizeof(char *));
    if (!envp) {
        return NULL;
    }
    size_t i = 0;
    for (ShVar *v = interp->vars; v; v = v->next) {
        if (v->exported && v->value) {
            size_t len = strlen(v->name) + 1 + strlen(v->value) + 1;
            char *entry = (char *)malloc(len);
            if (entry) {
                snprintf(entry, len, "%s=%s", v->name, v->value);
                envp[i++] = entry;
            }
        }
    }
    envp[i] = NULL;
    return envp;
}

void shFreeEnviron(char **envp) {
    if (!envp) {
        return;
    }
    for (size_t i = 0; envp[i]; ++i) {
        free(envp[i]);
    }
    free(envp);
}

/* ---- local scopes -------------------------------------------------------- */

void shVarMarkLocal(ShInterp *interp, const char *name) {
    if (!interp->func_frames) {
        return;
    }
    /* Don't double-save the same name within one frame. */
    for (ShLocalSave *s = interp->func_frames->locals; s; s = s->next) {
        if (strcmp(s->name, name) == 0) {
            return;
        }
    }
    ShLocalSave *save = (ShLocalSave *)calloc(1, sizeof(ShLocalSave));
    if (!save) {
        return;
    }
    save->name = strdup(name);
    ShVar *v = shVarFind(interp, name);
    if (v) {
        save->had_var = true;
        save->saved_value = v->value ? strdup(v->value) : NULL;
        save->was_exported = v->exported;
        save->was_read_only = v->read_only;
    }
    save->next = interp->func_frames->locals;
    interp->func_frames->locals = save;
}

/* Called by sh_exec.c when a function returns. */
void shPopLocalScope(ShInterp *interp);
void shPopLocalScope(ShInterp *interp) {
    ShFuncFrame *frame = interp->func_frames;
    if (!frame) {
        return;
    }
    interp->func_frames = frame->next;
    ShLocalSave *s = frame->locals;
    while (s) {
        ShLocalSave *next = s->next;
        ShVar *v = shVarFind(interp, s->name);
        if (v) {
            v->read_only = false; /* allow restore even if made readonly locally */
        }
        if (s->had_var) {
            shVarSet(interp, s->name, s->saved_value, false);
            v = shVarFind(interp, s->name);
            if (v) {
                v->exported = s->was_exported;
                v->read_only = s->was_read_only;
                if (!s->saved_value) {
                    free(v->value);
                    v->value = NULL;
                }
            }
        } else {
            shVarUnset(interp, s->name);
        }
        free(s->name);
        free(s->saved_value);
        free(s);
        s = next;
    }
    free(frame);
}

void shPushLocalScope(ShInterp *interp);
void shPushLocalScope(ShInterp *interp) {
    ShFuncFrame *frame = (ShFuncFrame *)calloc(1, sizeof(ShFuncFrame));
    if (!frame) {
        return;
    }
    frame->next = interp->func_frames;
    interp->func_frames = frame;
}

/* ---- functions ----------------------------------------------------------- */

/* Deep-copy helpers live in sh_astcopy.c. */
ShellProgram *shCopyProgram(const ShellProgram *program);

ShFunction *shFuncLookup(ShInterp *interp, const char *name) {
    for (ShFunction *f = interp->functions; f; f = f->next) {
        if (strcmp(f->name, name) == 0) {
            return f;
        }
    }
    return NULL;
}

int shFuncDefine(ShInterp *interp, const char *name, const ShellProgram *body) {
    ShellProgram *copy = shCopyProgram(body);
    if (!copy) {
        return 1;
    }
    ShFunction *f = shFuncLookup(interp, name);
    if (f) {
        shellFreeProgram(f->body);
        f->body = copy;
        return 0;
    }
    f = (ShFunction *)calloc(1, sizeof(ShFunction));
    if (!f) {
        shellFreeProgram(copy);
        return 1;
    }
    f->name = strdup(name);
    f->body = copy;
    f->next = interp->functions;
    interp->functions = f;
    return 0;
}

int shFuncUndefine(ShInterp *interp, const char *name) {
    ShFunction **link = &interp->functions;
    while (*link) {
        ShFunction *f = *link;
        if (strcmp(f->name, name) == 0) {
            *link = f->next;
            free(f->name);
            shellFreeProgram(f->body);
            free(f);
            return 0;
        }
        link = &f->next;
    }
    return 1;
}

/* ---- lifecycle ------------------------------------------------------------ */

ShInterp *shInterpCreate(void) {
    ShInterp *interp = (ShInterp *)calloc(1, sizeof(ShInterp));
    if (!interp) {
        return NULL;
    }
    interp->shell_pid = getpid();
    interp->next_job_id = 1;
    interp->tty_fd = -1;
    interp->trap_count = NSIG;
    interp->traps = (char **)calloc((size_t)NSIG, sizeof(char *));
    interp->pending_signals =
        (volatile sig_atomic_t *)calloc((size_t)NSIG, sizeof(sig_atomic_t));

    /* Seed shell variables from the process environment. */
    for (char **e = environ; e && *e; ++e) {
        const char *eq = strchr(*e, '=');
        if (!eq || eq == *e) {
            continue;
        }
        char *name = strndup(*e, (size_t)(eq - *e));
        if (name) {
            shVarSet(interp, name, eq + 1, true);
            free(name);
        }
    }

    /* Defaults per POSIX. */
    if (!shVarGet(interp, "IFS")) {
        shVarSet(interp, "IFS", " \t\n", false);
    }
    if (!shVarGet(interp, "PS1")) {
        shVarSet(interp, "PS1", geteuid() == 0 ? "# " : "$ ", false);
    }
    if (!shVarGet(interp, "PS2")) {
        shVarSet(interp, "PS2", "> ", false);
    }
    if (!shVarGet(interp, "PS4")) {
        shVarSet(interp, "PS4", "+ ", false);
    }
    if (!shVarGet(interp, "PATH")) {
        shVarSet(interp, "PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", true);
    }
    char ppid[32];
    snprintf(ppid, sizeof(ppid), "%ld", (long)getppid());
    shVarSet(interp, "PPID", ppid, false);

    return interp;
}

void shInterpDestroy(ShInterp *interp) {
    if (!interp) {
        return;
    }
    while (interp->func_frames) {
        shPopLocalScope(interp);
    }
    ShVar *v = interp->vars;
    while (v) {
        ShVar *next = v->next;
        free(v->name);
        free(v->value);
        free(v);
        v = next;
    }
    ShFunction *f = interp->functions;
    while (f) {
        ShFunction *next = f->next;
        free(f->name);
        shellFreeProgram(f->body);
        free(f);
        f = next;
    }
    ShJob *j = interp->jobs;
    while (j) {
        ShJob *next = j->next;
        free(j->pids);
        free(j->command);
        free(j);
        j = next;
    }
    if (interp->traps) {
        for (int i = 0; i < interp->trap_count; ++i) {
            free(interp->traps[i]);
        }
        free(interp->traps);
    }
    free((void *)interp->pending_signals);
    for (int i = 0; i < interp->param_count; ++i) {
        free(interp->params[i]);
    }
    free(interp->params);
    free(interp->arg0);
    free(interp);
}
