#include "openssh_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include "common/path_truncate.h"
#include "pscal_openssh_hooks.h"
#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#include "ios/tty/pscal_pty.h"
#if defined(__has_include)
#  if __has_include("PSCALRuntime.h")
#    include "PSCALRuntime.h"
#  else
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak_import));
extern void PSCALRuntimeInterposeBootstrap(void) __attribute__((weak_import));
extern void PSCALRuntimeRegisterSessionContext(uint64_t session_id) __attribute__((weak_import));
extern void PSCALRuntimeUnregisterSessionContext(uint64_t session_id) __attribute__((weak_import));
#  endif
#elif defined(__APPLE__)
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak_import));
extern void PSCALRuntimeInterposeBootstrap(void) __attribute__((weak_import));
extern void PSCALRuntimeRegisterSessionContext(uint64_t session_id) __attribute__((weak_import));
extern void PSCALRuntimeUnregisterSessionContext(uint64_t session_id) __attribute__((weak_import));
#else
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak));
extern void PSCALRuntimeInterposeBootstrap(void) __attribute__((weak));
extern void PSCALRuntimeRegisterSessionContext(uint64_t session_id) __attribute__((weak));
extern void PSCALRuntimeUnregisterSessionContext(uint64_t session_id) __attribute__((weak));
#endif
extern void pscalRuntimeDebugLog(const char *message) __attribute__((weak));
/* Provide a weak fallback so standalone smallclue builds without the runtime
 * bridge still link cleanly on iOS. The real runtime implementation overrides
 * this when available. */
__attribute__((weak))
jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) {
    (void)buffer;
    return NULL;
}
__attribute__((weak))
int PSCALRuntimePushExitOverride(jmp_buf *buffer) {
    (void)buffer;
    return -1;
}
__attribute__((weak))
void PSCALRuntimePopExitOverride(void) {
}
__attribute__((weak))
int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) {
    (void)buffer;
    (void)status_out;
    return -1;
}
__attribute__((weak))
void PSCALRuntimePopExitOverrideWithStatus(void) {
}

__attribute__((weak))
void PSCALRuntimeInterposeBootstrap(void) {
}

__attribute__((weak))
void PSCALRuntimeRegisterSessionContext(uint64_t session_id) {
    (void)session_id;
}

__attribute__((weak))
void PSCALRuntimeUnregisterSessionContext(uint64_t session_id) {
    (void)session_id;
}

__attribute__((weak))
void pscalRuntimeDebugLog(const char *message) {
    (void)message;
}
#endif

#if defined(PSCAL_TARGET_IOS)
__attribute__((weak))
int pscalRuntimeOpenSshSession(int argc, char **argv) {
    (void)argc;
    (void)argv;
    errno = ENOSYS;
    return -1;
}

__attribute__((weak))
void pscalRuntimeSshSessionExited(uint64_t session_id, int status) {
    (void)session_id;
    (void)status;
}
#endif

#if defined(PSCAL_TARGET_IOS)
static bool smallclueSshDebugEnabled(void) {
    const char *tool_debug = getenv("PSCALI_TOOL_DEBUG");
    const char *ssh_debug = getenv("PSCALI_SSH_DEBUG");
    if ((tool_debug && *tool_debug && strcmp(tool_debug, "0") != 0) ||
        (ssh_debug && *ssh_debug && strcmp(ssh_debug, "0") != 0)) {
        return true;
    }
    return false;
}

static void smallclueSshDebugLog(const char *message) {
    if (!message || !smallclueSshDebugEnabled()) {
        return;
    }
    if (pscalRuntimeDebugLog) {
        pscalRuntimeDebugLog(message);
    }
    fprintf(stderr, "%s\n", message);
}
#endif

int pscal_openssh_ssh_main(int argc, char **argv);
int pscal_openssh_scp_main(int argc, char **argv);
int pscal_openssh_sftp_main(int argc, char **argv);
int pscal_openssh_ssh_keygen_main(int argc, char **argv);
void pscal_openssh_set_global_exit_handler(sigjmp_buf *env,
                                           volatile sig_atomic_t *code_out);
void PSCALRuntimeSetDebugLogMirroring(int enable);
__attribute__((weak)) void PSCALRuntimeSetDebugLogMirroring(int enable) { (void)enable; }
void PSCALRuntimeBeginScriptCapture(const char *path, int append) __attribute__((weak));
void PSCALRuntimeEndScriptCapture(void) __attribute__((weak));
int PSCALRuntimeScriptCaptureActive(void) __attribute__((weak));
#if defined(PSCAL_TARGET_IOS)
int pscalRuntimeOpenSshSession(int argc, char **argv) __attribute__((weak));
#endif

volatile sig_atomic_t g_smallclue_openssh_exit_requested = 0;
static sigjmp_buf g_smallclue_openssh_fallback_env;
static volatile sig_atomic_t g_smallclue_openssh_fallback_active = 0;
static volatile sig_atomic_t g_smallclue_openssh_fallback_code = 0;

int pscal_openssh_fallback_exit(int code) {
    if (!g_smallclue_openssh_fallback_active) {
        return 0;
    }
    g_smallclue_openssh_fallback_code = code;
    siglongjmp(g_smallclue_openssh_fallback_env, 1);
    return 1; /* unreachable, but keeps the compiler happy */
}

static void smallclueFreeArgv(char **argv, int count) {
    if (!argv) {
        return;
    }
    for (int i = 0; i < count; ++i) {
        free(argv[i]);
    }
    free(argv);
}

static char *smallclueDupString(const char *value) {
    const char *src = value ? value : "";
    return strdup(src);
}

static char *smallclueDupEnv(const char *name) {
    if (!name) {
        return NULL;
    }
    const char *value = getenv(name);
    return value ? strdup(value) : NULL;
}

static void smallclueRestoreEnv(const char *name, const char *value) {
    if (!name) {
        return;
    }
    if (value) {
        setenv(name, value, 1);
    } else {
        unsetenv(name);
    }
}

static bool smallclueOptionKeyLooksPath(const char *key, size_t len) {
    if (!key || len < 4) {
        return false;
    }
    if (len >= 4 && strncasecmp(key + len - 4, "file", 4) == 0) {
        return true;
    }
    if (len >= 4 && strncasecmp(key + len - 4, "path", 4) == 0) {
        return true;
    }
    return false;
}

static char *smallclueExpandAbsolutePath(const char *path) {
    if (!path) {
        return smallclueDupString(path);
    }
    if (path[0] != '/') {
        return smallclueDupString(path);
    }
    char expanded[PATH_MAX];
    if (pathTruncateExpand(path, expanded, sizeof(expanded))) {
        return smallclueDupString(expanded);
    }
    return smallclueDupString(path);
}

static char *smallclueExpandOptionAssignment(const char *option) {
    if (!option) {
        return smallclueDupString(option);
    }
    const char *eq = strchr(option, '=');
    if (!eq) {
        return smallclueDupString(option);
    }
    size_t key_len = (size_t)(eq - option);
    if (!smallclueOptionKeyLooksPath(option, key_len)) {
        return smallclueDupString(option);
    }
    const char *value = eq + 1;
    if (value[0] != '/') {
        return smallclueDupString(option);
    }
    char expanded[PATH_MAX];
    if (!pathTruncateExpand(value, expanded, sizeof(expanded))) {
        return smallclueDupString(option);
    }
    size_t total = key_len + 1 + strlen(expanded) + 1;
    char *out = (char *)malloc(total);
    if (!out) {
        return smallclueDupString(option);
    }
    memcpy(out, option, key_len);
    out[key_len] = '=';
    memcpy(out + key_len + 1, expanded, strlen(expanded) + 1);
    return out;
}

static char *smallclueConcatOptionValue(const char *prefix, const char *value) {
    if (!prefix) {
        return smallclueDupString(value);
    }
    const char *val = value ? value : "";
    size_t total = strlen(prefix) + strlen(val) + 1;
    char *out = (char *)malloc(total);
    if (!out) {
        return smallclueDupString(prefix);
    }
    memcpy(out, prefix, strlen(prefix));
    memcpy(out + strlen(prefix), val, strlen(val) + 1);
    return out;
}

static char **smallclueExpandSshArgs(int argc, char **argv, int *out_count) {
    if (!argv || argc <= 0 || !out_count) {
        return NULL;
    }
    char **expanded = (char **)calloc((size_t)argc, sizeof(char *));
    if (!expanded) {
        return NULL;
    }
    int count = 0;
    bool stop = false;
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i] ? argv[i] : "";
        if (i == 0) {
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        if (stop) {
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            expanded[count++] = smallclueDupString(arg);
            stop = true;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            if (strcmp(arg, "-i") == 0 || strcmp(arg, "-F") == 0 ||
                strcmp(arg, "-E") == 0 || strcmp(arg, "-S") == 0 ||
                strcmp(arg, "-I") == 0) {
                expanded[count++] = smallclueDupString(arg);
                if (i + 1 < argc) {
                    expanded[count++] = smallclueExpandAbsolutePath(argv[++i]);
                }
                continue;
            }
            if (strcmp(arg, "-o") == 0) {
                expanded[count++] = smallclueDupString(arg);
                if (i + 1 < argc) {
                    expanded[count++] = smallclueExpandOptionAssignment(argv[++i]);
                }
                continue;
            }
            if ((arg[1] == 'i' || arg[1] == 'F' || arg[1] == 'E' ||
                 arg[1] == 'S' || arg[1] == 'I') && arg[2] != '\0') {
                char prefix[3] = { arg[0], arg[1], '\0' };
                char *value = smallclueExpandAbsolutePath(arg + 2);
                expanded[count++] = smallclueConcatOptionValue(prefix, value);
                free(value);
                continue;
            }
            if (arg[1] == 'o' && arg[2] != '\0') {
                char *value = smallclueExpandOptionAssignment(arg + 2);
                expanded[count++] = smallclueConcatOptionValue("-o", value);
                free(value);
                continue;
            }
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        stop = true;
        expanded[count++] = smallclueDupString(arg);
    }
    *out_count = count;
    return expanded;
}

static char **smallclueExpandScpArgs(int argc, char **argv, int *out_count) {
    if (!argv || argc <= 0 || !out_count) {
        return NULL;
    }
    char **expanded = (char **)calloc((size_t)argc, sizeof(char *));
    if (!expanded) {
        return NULL;
    }
    int count = 0;
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i] ? argv[i] : "";
        if (i == 0) {
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        if (strcmp(arg, "-i") == 0 || strcmp(arg, "-F") == 0 || strcmp(arg, "-S") == 0) {
            expanded[count++] = smallclueDupString(arg);
            if (i + 1 < argc) {
                expanded[count++] = smallclueExpandAbsolutePath(argv[++i]);
            }
            continue;
        }
        if (strcmp(arg, "-o") == 0) {
            expanded[count++] = smallclueDupString(arg);
            if (i + 1 < argc) {
                expanded[count++] = smallclueExpandOptionAssignment(argv[++i]);
            }
            continue;
        }
        if ((arg[1] == 'i' || arg[1] == 'F' || arg[1] == 'S') && arg[2] != '\0') {
            char prefix[3] = { arg[0], arg[1], '\0' };
            char *value = smallclueExpandAbsolutePath(arg + 2);
            expanded[count++] = smallclueConcatOptionValue(prefix, value);
            free(value);
            continue;
        }
        if (arg[0] == '-' && arg[1] == 'o' && arg[2] != '\0') {
            char *value = smallclueExpandOptionAssignment(arg + 2);
            expanded[count++] = smallclueConcatOptionValue("-o", value);
            free(value);
            continue;
        }
        if (arg[0] == '/' && strchr(arg, ':') == NULL) {
            expanded[count++] = smallclueExpandAbsolutePath(arg);
            continue;
        }
        expanded[count++] = smallclueDupString(arg);
    }
    *out_count = count;
    return expanded;
}

static char **smallclueExpandSftpArgs(int argc, char **argv, int *out_count) {
    if (!argv || argc <= 0 || !out_count) {
        return NULL;
    }
    char **expanded = (char **)calloc((size_t)argc, sizeof(char *));
    if (!expanded) {
        return NULL;
    }
    int count = 0;
    bool stop = false;
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i] ? argv[i] : "";
        if (i == 0) {
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        if (stop) {
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            expanded[count++] = smallclueDupString(arg);
            stop = true;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            if (strcmp(arg, "-b") == 0 || strcmp(arg, "-F") == 0 ||
                strcmp(arg, "-i") == 0 || strcmp(arg, "-S") == 0 ||
                strcmp(arg, "-D") == 0 || strcmp(arg, "-s") == 0) {
                expanded[count++] = smallclueDupString(arg);
                if (i + 1 < argc) {
                    expanded[count++] = smallclueExpandAbsolutePath(argv[++i]);
                }
                continue;
            }
            if (strcmp(arg, "-o") == 0) {
                expanded[count++] = smallclueDupString(arg);
                if (i + 1 < argc) {
                    expanded[count++] = smallclueExpandOptionAssignment(argv[++i]);
                }
                continue;
            }
            if (arg[1] == 'o' && arg[2] != '\0') {
                char *value = smallclueExpandOptionAssignment(arg + 2);
                expanded[count++] = smallclueConcatOptionValue("-o", value);
                free(value);
                continue;
            }
            expanded[count++] = smallclueDupString(arg);
            continue;
        }
        stop = true;
        expanded[count++] = smallclueDupString(arg);
    }
    *out_count = count;
    return expanded;
}

static void smallclueEnsureWritableHomeSsh(void) {
    const char *home = getenv("PSCALI_WORKDIR");
    if (!home || !*home) {
        home = getenv("PSCALI_CONTAINER_ROOT");
    }
    if (!home || !*home) {
        home = getenv("HOME");
    }
    if (!home || !*home) {
        home = ".";
    }

    char ssh_dir[PATH_MAX];
    int written = snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    if (written > 0 && written < (int)sizeof(ssh_dir)) {
        struct stat st;
        if (stat(ssh_dir, &st) != 0) {
            mkdir(ssh_dir, 0700);
        }
    }

    setenv("HOME", home, 1);
}

static bool smallclueApplyVirtualHome(char **saved_home, char **saved_pscali_home) {
    if (saved_home) {
        *saved_home = NULL;
    }
    if (saved_pscali_home) {
        *saved_pscali_home = NULL;
    }
    if (!pathTruncateEnabled()) {
        return false;
    }
    const char *home = getenv("HOME");
    if (!home || home[0] != '/') {
        return false;
    }
    char stripped[PATH_MAX];
    if (!pathTruncateStrip(home, stripped, sizeof(stripped))) {
        return false;
    }
    if (strcmp(stripped, home) == 0) {
        return false;
    }
    if (saved_home) {
        *saved_home = smallclueDupString(home);
    }
    if (saved_pscali_home) {
        *saved_pscali_home = smallclueDupEnv("PSCALI_HOME");
    }
    setenv("HOME", stripped, 1);
    setenv("PSCALI_HOME", stripped, 1);
    return true;
}

typedef struct {
    char *askpass;
    char *askpass_require;
    char *display;
    char *wayland_display;
} smallclueSshAskpassEnv;

static bool smallclueApplySshPromptEnv(smallclueSshAskpassEnv *env) {
#if defined(PSCAL_TARGET_IOS)
    if (!env) {
        return false;
    }
    env->askpass = smallclueDupEnv("SSH_ASKPASS");
    env->askpass_require = smallclueDupEnv("SSH_ASKPASS_REQUIRE");
    env->display = smallclueDupEnv("DISPLAY");
    env->wayland_display = smallclueDupEnv("WAYLAND_DISPLAY");
    setenv("SSH_ASKPASS_REQUIRE", "never", 1);
    unsetenv("SSH_ASKPASS");
    setenv("DISPLAY", "", 1);
    setenv("WAYLAND_DISPLAY", "", 1);
    return true;
#else
    (void)env;
    return false;
#endif
}

static void smallclueRestoreSshPromptEnv(smallclueSshAskpassEnv *env) {
#if defined(PSCAL_TARGET_IOS)
    if (!env) {
        return;
    }
    smallclueRestoreEnv("SSH_ASKPASS", env->askpass);
    smallclueRestoreEnv("SSH_ASKPASS_REQUIRE", env->askpass_require);
    smallclueRestoreEnv("DISPLAY", env->display);
    smallclueRestoreEnv("WAYLAND_DISPLAY", env->wayland_display);
    free(env->askpass);
    free(env->askpass_require);
    free(env->display);
    free(env->wayland_display);
    env->askpass = NULL;
    env->askpass_require = NULL;
    env->display = NULL;
    env->wayland_display = NULL;
#else
    (void)env;
#endif
}

static int smallclueInvokeOpensshEntry(const char *label, int (*entry)(int, char **),
                                       int argc, char **argv) {
    g_smallclue_openssh_exit_requested = 0;
    if (!entry) {
        fprintf(stderr, "%s: command unavailable\n", label ? label : "ssh");
        return 127;
    }
#if defined(PSCAL_TARGET_IOS)
    bool mirror_debug = false;
    const char *tool_debug = getenv("PSCALI_TOOL_DEBUG");
    const char *ssh_debug = getenv("PSCALI_SSH_DEBUG");
    if ((tool_debug && *tool_debug && strcmp(tool_debug, "0") != 0) ||
        (ssh_debug && *ssh_debug && strcmp(ssh_debug, "0") != 0)) {
        mirror_debug = true;
    }
#endif
    pscal_openssh_exit_context exitContext;
    pscal_openssh_reset_progress_state();
    pscal_openssh_push_exit_context(&exitContext);
#if defined(PSCAL_TARGET_IOS)
    if (mirror_debug) {
        PSCALRuntimeSetDebugLogMirroring(1);
    }
#endif
    int status;
    if (sigsetjmp(exitContext.env, 0) == 0) {
        status = entry(argc, argv);
    } else {
        status = exitContext.exit_code;
    }
#if defined(PSCAL_TARGET_IOS)
    if (mirror_debug) {
        PSCALRuntimeSetDebugLogMirroring(0);
    }
#endif
    pscal_openssh_pop_exit_context(&exitContext);
    return status;
}

static int smallclueRunOpensshEntryOnce(const char *label, int (*entry)(int, char **),
                                        int argc, char **argv) {
    if (!entry) {
        fprintf(stderr, "%s: command unavailable\n", label ? label : "ssh");
        return 127;
    }
    struct sigaction old_pipe;
    struct sigaction ignore_action;
    memset(&ignore_action, 0, sizeof(ignore_action));
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&ignore_action.sa_mask);
    sigaction(SIGPIPE, &ignore_action, &old_pipe);
    int status = 255;
#if defined(PSCAL_TARGET_IOS)
    jmp_buf exit_env;
    volatile int exit_status_sink = 0;
    bool override_active = false;
    if (PSCALRuntimePushExitOverrideWithStatus &&
        PSCALRuntimePushExitOverrideWithStatus(&exit_env, &exit_status_sink) == 0) {
        override_active = true;
        int jump_code = setjmp(exit_env);
        if (jump_code != 0) {
            status = (jump_code == 1) ? exit_status_sink : jump_code;
            goto smallclue_openssh_done;
        }
    } else if (PSCALRuntimePushExitOverride && PSCALRuntimePushExitOverride(&exit_env) == 0) {
        override_active = true;
        int jump_code = setjmp(exit_env);
        if (jump_code != 0) {
            status = (jump_code == 1) ? 0 : jump_code;
            goto smallclue_openssh_done;
        }
    }
    int jump_code_outer = sigsetjmp(g_smallclue_openssh_fallback_env, 0);
    if (jump_code_outer != 0) {
        status = g_smallclue_openssh_fallback_code;
        goto smallclue_openssh_done;
    }
    g_smallclue_openssh_fallback_active = 1;
    pscal_openssh_set_global_exit_handler(&g_smallclue_openssh_fallback_env,
                                          &g_smallclue_openssh_fallback_code);
    status = smallclueInvokeOpensshEntry(label, entry, argc, argv);
smallclue_openssh_done:
    g_smallclue_openssh_fallback_active = 0;
    if (override_active) {
        if (PSCALRuntimePopExitOverrideWithStatus) {
            PSCALRuntimePopExitOverrideWithStatus();
        } else if (PSCALRuntimePopExitOverride) {
            PSCALRuntimePopExitOverride();
        }
    }
#if defined(PSCAL_TARGET_IOS)
    pscal_openssh_set_global_exit_handler(NULL, NULL);
#endif
#else
    status = smallclueInvokeOpensshEntry(label, entry, argc, argv);
#endif
    sigaction(SIGPIPE, &old_pipe, NULL);
    return status;
}

#if defined(PSCAL_TARGET_IOS)
typedef struct {
    const char *label;
    int (*entry)(int, char **);
    int argc;
    char **argv;
    VProc *vp;
    VProcSessionStdio *session_stdio;
} smallclueOpensshThreadContext;

static void *smallclueRunOpensshEntryThread(void *arg) {
    smallclueOpensshThreadContext *ctx = (smallclueOpensshThreadContext *)arg;
    bool activated = false;
    VProcSessionStdio *prev_stdio = NULL;
    bool stdio_swapped = false;
    if (ctx && ctx->vp) {
        vprocActivate(ctx->vp);
        vprocRegisterThread(ctx->vp, pthread_self());
        activated = true;
    }
    if (ctx && ctx->session_stdio) {
        prev_stdio = vprocSessionStdioCurrent();
        vprocSessionStdioActivate(ctx->session_stdio);
        stdio_swapped = true;
    }
    int status = smallclueRunOpensshEntryOnce(ctx->label, ctx->entry, ctx->argc, ctx->argv);
    if (stdio_swapped) {
        vprocSessionStdioActivate(prev_stdio);
    }
    if (activated) {
        vprocUnregisterThread(ctx->vp, pthread_self());
        vprocDeactivate();
    }
    return (void *)(intptr_t)status;
}

static int smallclueRunOpensshEntry(const char *label, int (*entry)(int, char **),
                                    int argc, char **argv) {
    smallclueOpensshThreadContext ctx = {
        .label = label,
        .entry = entry,
        .argc = argc,
        .argv = argv,
        .vp = vprocCurrent(),
        .session_stdio = vprocSessionStdioCurrent()
    };
    pthread_t thread;
    int err = pthread_create(&thread, NULL, smallclueRunOpensshEntryThread, &ctx);
    if (err != 0) {
        return smallclueRunOpensshEntryOnce(label, entry, argc, argv);
    }
    void *thread_ret = NULL;
    pthread_join(thread, &thread_ret);
    return (int)(intptr_t)thread_ret;
}

extern void pscalRuntimeSshSessionExited(uint64_t session_id, int status) __attribute__((weak));

typedef struct {
    int argc;
    char **argv;
    struct pscal_fd *pty_master;
    struct pscal_fd *pty_slave;
    uint64_t session_id;
} smallclueSshSessionContext;

static void smallclueSshSessionNotifyExit(uint64_t session_id, int status) {
    if (pscalRuntimeSshSessionExited) {
        pscalRuntimeSshSessionExited(session_id, status);
    }
}

static void smallclueCloseSessionFds(smallclueSshSessionContext *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->pty_master) {
        pscal_fd_close(ctx->pty_master);
        ctx->pty_master = NULL;
    }
    if (ctx->pty_slave) {
        pscal_fd_close(ctx->pty_slave);
        ctx->pty_slave = NULL;
    }
}

static void *smallclueRunSshSessionThread(void *arg) {
    smallclueSshSessionContext *ctx = (smallclueSshSessionContext *)arg;
    if (!ctx) {
        return NULL;
    }
    if (smallclueSshDebugEnabled()) {
        char logbuf[192];
        snprintf(logbuf, sizeof(logbuf),
                 "[ssh-session] thread start session=%llu",
                 (unsigned long long)ctx->session_id);
        smallclueSshDebugLog(logbuf);
    }
    int status = 255;
    int kernel_pid = vprocEnsureKernelPid();
    VProcSessionStdio *session_stdio = vprocSessionStdioCreate();
    if (!session_stdio) {
        smallclueCloseSessionFds(ctx);
        smallclueSshSessionNotifyExit(ctx->session_id, status);
        smallclueFreeArgv(ctx->argv, ctx->argc);
        free(ctx);
        return NULL;
    }
    if (vprocSessionStdioInitWithPty(session_stdio,
                                     ctx->pty_slave,
                                     ctx->pty_master,
                                     ctx->session_id,
                                     kernel_pid) != 0) {
        vprocSessionStdioDestroy(session_stdio);
        smallclueCloseSessionFds(ctx);
        smallclueSshSessionNotifyExit(ctx->session_id, status);
        smallclueFreeArgv(ctx->argv, ctx->argc);
        free(ctx);
        return NULL;
    }
    vprocSessionStdioActivate(session_stdio);
    ctx->pty_slave = NULL;
    ctx->pty_master = NULL;

    VProcOptions opts = vprocDefaultOptions();
    bool use_pscal_stdio = session_stdio && session_stdio->stdin_pscal_fd;
    opts.stdin_fd = use_pscal_stdio ? -2 : session_stdio->stdin_host_fd;
    opts.stdout_fd = use_pscal_stdio ? -2 : session_stdio->stdout_host_fd;
    opts.stderr_fd = use_pscal_stdio ? -2 : session_stdio->stderr_host_fd;
    opts.pid_hint = vprocReservePid();
    VProc *vp = vprocCreate(&opts);
    if (vp) {
        if (!session_stdio) {
            smallclueCloseSessionFds(ctx);
        }
        vprocActivate(vp);
        if (use_pscal_stdio) {
            (void)vprocAdoptPscalStdio(vp,
                                       session_stdio->stdin_pscal_fd,
                                       session_stdio->stdout_pscal_fd,
                                       session_stdio->stderr_pscal_fd);
        }
        vprocRegisterThread(vp, pthread_self());
        int pid = vprocPid(vp);
        if (kernel_pid > 0 && kernel_pid != pid) {
            vprocSetParent(pid, kernel_pid);
        }
        (void)vprocSetSid(pid, pid);
        (void)vprocSetPgid(pid, pid);
        (void)vprocSetForegroundPgid(pid, pid);
        vprocSetCommandLabel(pid, (ctx->argv && ctx->argv[0]) ? ctx->argv[0] : "ssh");
        if (smallclueSshDebugEnabled()) {
            char logbuf[192];
            snprintf(logbuf, sizeof(logbuf),
                     "[ssh-session] vproc created session=%llu pid=%d",
                     (unsigned long long)ctx->session_id,
                     pid);
            smallclueSshDebugLog(logbuf);
        }
    } else {
        status = 255;
        if (getenv("PSCALI_TOOL_DEBUG")) {
            fprintf(stderr, "[ssh-session] vproc create failed\n");
        }
        smallclueSshDebugLog("[ssh-session] vproc create failed");
    }

    if (vp) {
        smallclueSshDebugLog("[ssh-session] openssh entry start");
        status = smallclueRunOpensshEntryOnce("ssh", pscal_openssh_ssh_main, ctx->argc, ctx->argv);
    }

    if (vp) {
        vprocUnregisterThread(vp, pthread_self());
        vprocDeactivate();
        vprocMarkExit(vp, status);
        vprocDestroy(vp);
    }

    if (session_stdio) {
        vprocSessionStdioActivate(NULL);
        vprocSessionStdioDestroy(session_stdio);
    }

    if (smallclueSshDebugEnabled()) {
        char logbuf[192];
        snprintf(logbuf, sizeof(logbuf),
                 "[ssh-session] thread exit session=%llu status=%d",
                 (unsigned long long)ctx->session_id,
                 status);
        smallclueSshDebugLog(logbuf);
    }
    smallclueSshSessionNotifyExit(ctx->session_id, status);
    smallclueFreeArgv(ctx->argv, ctx->argc);
    free(ctx);
    return NULL;
}

int PSCALRuntimeCreateSshSession(int argc,
                                 char **argv,
                                 uint64_t session_id,
                                 int *out_read_fd,
                                 int *out_write_fd) {
    if (argc <= 0 || !argv) {
        errno = EINVAL;
        return -1;
    }
    if (!out_read_fd || !out_write_fd) {
        errno = EINVAL;
        return -1;
    }
    *out_read_fd = -1;
    *out_write_fd = -1;

    if (smallclueSshDebugEnabled()) {
        const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "(null)";
        char logbuf[192];
        snprintf(logbuf, sizeof(logbuf),
                 "[ssh-session] create start session=%llu argc=%d argv0=%s",
                 (unsigned long long)session_id,
                 argc,
                 argv0);
        smallclueSshDebugLog(logbuf);
    }

    PSCALRuntimeInterposeBootstrap();
    (void)vprocEnsureKernelPid();

    struct pscal_fd *pty_master = NULL;
    struct pscal_fd *pty_slave = NULL;
    int pty_num = -1;
    int pty_err = pscalPtyOpenMaster(O_RDWR, &pty_master, &pty_num);
    if (pty_err < 0) {
        if (smallclueSshDebugEnabled()) {
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf),
                     "[ssh-session] pty master failed err=%d",
                     pty_err);
            smallclueSshDebugLog(logbuf);
        }
        errno = pscalCompatErrno(pty_err);
        return -1;
    }
    pty_err = pscalPtyUnlock(pty_master);
    if (pty_err < 0) {
        if (pty_master) pscal_fd_close(pty_master);
        if (smallclueSshDebugEnabled()) {
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf),
                     "[ssh-session] pty unlock failed err=%d",
                     pty_err);
            smallclueSshDebugLog(logbuf);
        }
        errno = pscalCompatErrno(pty_err);
        return -1;
    }
    pty_err = pscalPtyOpenSlave(pty_num, O_RDWR, &pty_slave);
    if (pty_err < 0) {
        if (pty_master) pscal_fd_close(pty_master);
        if (smallclueSshDebugEnabled()) {
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf),
                     "[ssh-session] pty slave failed err=%d",
                     pty_err);
            smallclueSshDebugLog(logbuf);
        }
        errno = pscalCompatErrno(pty_err);
        return -1;
    }

    smallclueSshSessionContext *ctx = (smallclueSshSessionContext *)calloc(1, sizeof(smallclueSshSessionContext));
    if (!ctx) {
        errno = ENOMEM;
        if (pty_master) pscal_fd_close(pty_master);
        if (pty_slave) pscal_fd_close(pty_slave);
        return -1;
    }
    ctx->argc = argc;
    ctx->pty_master = pty_master;
    ctx->pty_slave = pty_slave;
    ctx->session_id = session_id;
    ctx->argv = (char **)calloc((size_t)argc, sizeof(char *));
    if (!ctx->argv) {
        smallclueCloseSessionFds(ctx);
        free(ctx);
        errno = ENOMEM;
        return -1;
    }
    for (int i = 0; i < argc; ++i) {
        ctx->argv[i] = smallclueDupString(argv[i]);
        if (!ctx->argv[i]) {
            smallclueFreeArgv(ctx->argv, i);
            free(ctx);
            errno = ENOMEM;
            return -1;
        }
    }

    if (PSCALRuntimeRegisterSessionContext) {
        PSCALRuntimeRegisterSessionContext(session_id);
    }

    pthread_t thread;
    int err = vprocHostPthreadCreate(&thread, NULL, smallclueRunSshSessionThread, ctx);
    if (err != 0) {
        if (smallclueSshDebugEnabled()) {
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf),
                     "[ssh-session] thread create failed err=%d",
                     err);
            smallclueSshDebugLog(logbuf);
        }
        if (PSCALRuntimeUnregisterSessionContext) {
            PSCALRuntimeUnregisterSessionContext(session_id);
        }
        smallclueFreeArgv(ctx->argv, ctx->argc);
        smallclueCloseSessionFds(ctx);
        free(ctx);
        errno = err;
        return -1;
    }
    if (smallclueSshDebugEnabled()) {
        char logbuf[128];
        snprintf(logbuf, sizeof(logbuf),
                 "[ssh-session] thread created session=%llu pty=%d",
                 (unsigned long long)session_id,
                 pty_num);
        smallclueSshDebugLog(logbuf);
    }
    pthread_detach(thread);
    return 0;
}
#else
static int smallclueRunOpensshEntry(const char *label, int (*entry)(int, char **),
                                    int argc, char **argv) {
    return smallclueRunOpensshEntryOnce(label, entry, argc, argv);
}
#endif

int smallclueRunSsh(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    char *saved_home = NULL;
    char *saved_pscali_home = NULL;
    bool restore_home = smallclueApplyVirtualHome(&saved_home, &saved_pscali_home);
    smallclueSshAskpassEnv askpass_env = {0};
    bool restore_askpass = smallclueApplySshPromptEnv(&askpass_env);
    if (argc < 2) {
        fprintf(stderr, "usage: ssh [options] host [command]\n");
        if (restore_home) {
            smallclueRestoreEnv("HOME", saved_home);
            smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
        }
        free(saved_home);
        free(saved_pscali_home);
        return 255;
    }
    /* Preserve user args; only ensure -tt for interactive sessions. */
    bool has_tty_flag = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-t") == 0 || strcmp(arg, "-tt") == 0) {
            has_tty_flag = true;
            break;
        }
    }

    int extra = has_tty_flag ? 0 : 1;
    int new_argc = argc + extra;
    char **augmented = (char **)calloc((size_t)new_argc, sizeof(char *));
    if (!augmented) {
        int status = smallclueRunOpensshEntry("ssh", pscal_openssh_ssh_main, argc, argv);
        if (restore_home) {
            smallclueRestoreEnv("HOME", saved_home);
            smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
        }
        free(saved_home);
        free(saved_pscali_home);
        return status;
    }
    int count = 0;
    if (argc > 0 && argv && argv[0]) {
        augmented[count++] = strdup(argv[0]);
    } else {
        augmented[count++] = strdup("ssh");
    }
    if (!has_tty_flag) {
        augmented[count++] = strdup("-tt");
    }
    for (int i = 1; i < argc; ++i) {
        augmented[count++] = argv[i] ? strdup(argv[i]) : strdup("");
    }

    int expanded_count = 0;
    char **expanded = smallclueExpandSshArgs(count, augmented, &expanded_count);
    int status = 255;
    status = smallclueRunOpensshEntry("ssh", pscal_openssh_ssh_main,
                                      expanded ? expanded_count : count,
                                      expanded ? expanded : augmented);
    if (expanded) {
        smallclueFreeArgv(expanded, expanded_count);
    }
    smallclueFreeArgv(augmented, count);
    if (restore_askpass) {
        smallclueRestoreSshPromptEnv(&askpass_env);
    }
    if (restore_home) {
        smallclueRestoreEnv("HOME", saved_home);
        smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
    }
    free(saved_home);
    free(saved_pscali_home);
    return status;
}

int smallclueRunScp(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    char *saved_home = NULL;
    char *saved_pscali_home = NULL;
    bool restore_home = smallclueApplyVirtualHome(&saved_home, &saved_pscali_home);
    smallclueSshAskpassEnv askpass_env = {0};
    bool restore_askpass = smallclueApplySshPromptEnv(&askpass_env);
    int expanded_count = 0;
    char **expanded = smallclueExpandScpArgs(argc, argv, &expanded_count);
    int status = smallclueRunOpensshEntry("scp", pscal_openssh_scp_main,
                                          expanded ? expanded_count : argc,
                                          expanded ? expanded : argv);
    if (expanded) {
        smallclueFreeArgv(expanded, expanded_count);
    }
    if (restore_askpass) {
        smallclueRestoreSshPromptEnv(&askpass_env);
    }
    if (restore_home) {
        smallclueRestoreEnv("HOME", saved_home);
        smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
    }
    free(saved_home);
    free(saved_pscali_home);
    return status;
}

int smallclueRunSftp(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    char *saved_home = NULL;
    char *saved_pscali_home = NULL;
    bool restore_home = smallclueApplyVirtualHome(&saved_home, &saved_pscali_home);
    smallclueSshAskpassEnv askpass_env = {0};
    bool restore_askpass = smallclueApplySshPromptEnv(&askpass_env);
    int expanded_count = 0;
    char **expanded = smallclueExpandSftpArgs(argc, argv, &expanded_count);
    int status = smallclueRunOpensshEntry("sftp", pscal_openssh_sftp_main,
                                          expanded ? expanded_count : argc,
                                          expanded ? expanded : argv);
    if (expanded) {
        smallclueFreeArgv(expanded, expanded_count);
    }
    if (restore_askpass) {
        smallclueRestoreSshPromptEnv(&askpass_env);
    }
    if (restore_home) {
        smallclueRestoreEnv("HOME", saved_home);
        smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
    }
    free(saved_home);
    free(saved_pscali_home);
    return status;
}

int smallclueRunSshKeygen(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    char *saved_home = NULL;
    char *saved_pscali_home = NULL;
    bool restore_home = smallclueApplyVirtualHome(&saved_home, &saved_pscali_home);
    int status = smallclueRunOpensshEntry("ssh-keygen", pscal_openssh_ssh_keygen_main, argc, argv);
    if (restore_home) {
        smallclueRestoreEnv("HOME", saved_home);
        smallclueRestoreEnv("PSCALI_HOME", saved_pscali_home);
    }
    free(saved_home);
    free(saved_pscali_home);
    return status;
}
