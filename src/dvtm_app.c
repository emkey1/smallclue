#include "dvtm_app.h"
#include "dvtm_runtime_hooks.h"

#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(SMALLCLUE_WITH_DVTM)
extern int dvtm_main_entry(int argc, char **argv);

static bool smallclueDvtmDebugEnabled(void) {
    const char *debug_env = getenv("PSCALI_DVTM_DEBUG");
    return debug_env && debug_env[0] && strcmp(debug_env, "0") != 0;
}

static void smallclueDvtmDebugf(const char *fmt, ...) {
    if (!smallclueDvtmDebugEnabled() || !fmt) {
        return;
    }
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
}

static bool smallclueDvtmPathExecutable(const char *path) {
    return path && path[0] == '/' && access(path, X_OK) == 0;
}

static bool smallclueDvtmPathJoin(char *out, size_t out_size,
                                  const char *left, const char *right) {
    if (!out || out_size == 0 || !left || !right || !left[0] || !right[0]) {
        return false;
    }
    int written = snprintf(out, out_size, "%s/%s", left, right);
    return written > 0 && (size_t)written < out_size;
}

static bool smallclueDvtmResolveCommandOnPath(const char *name, char *out, size_t out_size) {
    if (!name || !name[0] || !out || out_size == 0) {
        return false;
    }
    out[0] = '\0';
    const char *path = getenv("PATH");
    if (!path || !path[0]) {
        return false;
    }

    char path_copy[PATH_MAX * 2];
    size_t path_len = strlen(path);
    if (path_len >= sizeof(path_copy)) {
        path_len = sizeof(path_copy) - 1;
    }
    memcpy(path_copy, path, path_len);
    path_copy[path_len] = '\0';

    char *saveptr = NULL;
    char *segment = strtok_r(path_copy, ":", &saveptr);
    while (segment) {
        char candidate[PATH_MAX];
        if (segment[0] == '\0') {
            segment = ".";
        }
        if (smallclueDvtmPathJoin(candidate, sizeof(candidate), segment, name) &&
            smallclueDvtmPathExecutable(candidate)) {
            snprintf(out, out_size, "%s", candidate);
            return true;
        }
        segment = strtok_r(NULL, ":", &saveptr);
    }
    return false;
}

static bool smallclueDvtmIsDvtmBinary(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    const char *base = strrchr(path, '/');
    base = base ? (base + 1) : path;
    return strcmp(base, "dvtm") == 0;
}

static bool smallclueDvtmResolveExshPath(char *out, size_t out_size) {
    if (!out || out_size == 0) {
        return false;
    }
    out[0] = '\0';

    const char *container_root = getenv("PSCALI_CONTAINER_ROOT");
    const char *workspace_root = getenv("PSCALI_WORKSPACE_ROOT");
    char candidate[PATH_MAX];
    if (container_root && container_root[0] == '/') {
        if (smallclueDvtmPathJoin(candidate, sizeof(candidate), container_root, "Documents/bin/exsh") &&
            smallclueDvtmPathExecutable(candidate)) {
            snprintf(out, out_size, "%s", candidate);
            return true;
        }
    }
    if (workspace_root && workspace_root[0] == '/') {
        if (smallclueDvtmPathJoin(candidate, sizeof(candidate), workspace_root, "bin/exsh") &&
            smallclueDvtmPathExecutable(candidate)) {
            snprintf(out, out_size, "%s", candidate);
            return true;
        }
    }
    if (smallclueDvtmPathExecutable("/bin/exsh")) {
        snprintf(out, out_size, "%s", "/bin/exsh");
        return true;
    }
    if (smallclueDvtmPathExecutable("/usr/bin/exsh")) {
        snprintf(out, out_size, "%s", "/usr/bin/exsh");
        return true;
    }
    if (smallclueDvtmResolveCommandOnPath("exsh", out, out_size)) {
        return true;
    }
    if (smallclueDvtmResolveCommandOnPath("smallclue", out, out_size)) {
        return true;
    }
    return false;
}

static const char *smallclueDvtmSelectShell(const char *saved_shell) {
    static char resolved_shell[PATH_MAX];
    resolved_shell[0] = '\0';

    const char *forced = getenv("PSCALI_DVTM_SHELL");
    if (smallclueDvtmPathExecutable(forced) && !smallclueDvtmIsDvtmBinary(forced)) {
        return forced;
    }
    if (forced && forced[0] && forced[0] != '/') {
        if (smallclueDvtmResolveCommandOnPath(forced, resolved_shell, sizeof(resolved_shell)) &&
            !smallclueDvtmIsDvtmBinary(resolved_shell)) {
            return resolved_shell;
        }
    }
    if (smallclueDvtmPathExecutable(saved_shell) && !smallclueDvtmIsDvtmBinary(saved_shell)) {
        return saved_shell;
    }
    if (saved_shell && saved_shell[0] && saved_shell[0] != '/') {
        if (smallclueDvtmResolveCommandOnPath(saved_shell, resolved_shell, sizeof(resolved_shell)) &&
            !smallclueDvtmIsDvtmBinary(resolved_shell)) {
            return resolved_shell;
        }
    }

    /* In PSCAL environments, exsh is the canonical interactive shell. */
    if (smallclueDvtmResolveExshPath(resolved_shell, sizeof(resolved_shell))) {
        return resolved_shell;
    }

    static const char *fallbacks[] = { "/bin/sh", "/usr/bin/sh", "/system/bin/sh" };
    for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); ++i) {
        if (smallclueDvtmPathExecutable(fallbacks[i])) {
            return fallbacks[i];
        }
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_shell && smallclueDvtmPathExecutable(pw->pw_shell) &&
        !smallclueDvtmIsDvtmBinary(pw->pw_shell)) {
        return pw->pw_shell;
    }
    return NULL;
}

static pthread_key_t g_dvtmExitContextKey;
static pthread_once_t g_dvtmExitContextOnce = PTHREAD_ONCE_INIT;

static void smallclueInitDvtmExitContextKey(void) {
    (void)pthread_key_create(&g_dvtmExitContextKey, NULL);
}

void smallclueDvtmPushExitContext(DvtmExitContext *ctx) {
    if (!ctx) {
        return;
    }
    pthread_once(&g_dvtmExitContextOnce, smallclueInitDvtmExitContextKey);
    ctx->prev = (DvtmExitContext *)pthread_getspecific(g_dvtmExitContextKey);
    ctx->exit_code = 1;
    pthread_setspecific(g_dvtmExitContextKey, ctx);
}

void smallclueDvtmPopExitContext(DvtmExitContext *ctx) {
    if (!ctx) {
        return;
    }
    pthread_once(&g_dvtmExitContextOnce, smallclueInitDvtmExitContextKey);
    pthread_setspecific(g_dvtmExitContextKey, ctx->prev);
}

_Noreturn void pscalDvtmRequestExit(int code) {
    pthread_once(&g_dvtmExitContextOnce, smallclueInitDvtmExitContextKey);
    DvtmExitContext *ctx = (DvtmExitContext *)pthread_getspecific(g_dvtmExitContextKey);
    if (ctx) {
        ctx->exit_code = code;
        siglongjmp(ctx->env, 1);
    }
    _Exit(code);
}

int smallclueRunDvtm(int argc, char **argv) {
    const char *saved_term = getenv("TERM");
    const char *saved_shell = getenv("SHELL");
    char *saved_term_copy = NULL;
    char *saved_shell_copy = NULL;
    if (saved_term && saved_term[0] != '\0') {
        saved_term_copy = strdup(saved_term);
    } else {
        setenv("TERM", "xterm-256color", 1);
    }
    if (saved_shell && saved_shell[0] != '\0') {
        saved_shell_copy = strdup(saved_shell);
    }
    const char *chosen_shell = smallclueDvtmSelectShell(saved_shell_copy ? saved_shell_copy : saved_shell);
    if (chosen_shell && chosen_shell[0] != '\0') {
        setenv("SHELL", chosen_shell, 1);
    } else {
        unsetenv("SHELL");
    }
    if (!getenv("DVTM_TERM")) {
        setenv("DVTM_TERM", "xterm-256color", 1);
    }
    smallclueDvtmDebugf("[dvtm] launch argc=%d term=%s shell=%s",
                        argc,
                        getenv("TERM") ? getenv("TERM") : "(null)",
                        getenv("SHELL") ? getenv("SHELL") : "(null)");

    int status = 1;
    DvtmExitContext ctx;
    smallclueDvtmPushExitContext(&ctx);
    if (sigsetjmp(ctx.env, 1) == 0) {
        status = dvtm_main_entry(argc, argv);
    } else {
        status = ctx.exit_code;
    }
    smallclueDvtmPopExitContext(&ctx);
    smallclueDvtmDebugf("[dvtm] exit status=%d", status);

    if (saved_term_copy) {
        setenv("TERM", saved_term_copy, 1);
    } else {
        unsetenv("TERM");
    }
    if (saved_shell_copy) {
        setenv("SHELL", saved_shell_copy, 1);
    } else if (saved_shell) {
        setenv("SHELL", saved_shell, 1);
    } else {
        unsetenv("SHELL");
    }
    free(saved_term_copy);
    free(saved_shell_copy);
    return status;
}
#else
int smallclueRunDvtm(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("dvtm: applet is disabled in this build (enable SMALLCLUE_WITH_DVTM)\n", stderr);
    return 127;
}
#endif
