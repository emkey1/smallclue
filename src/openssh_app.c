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
#include "pscal_openssh_hooks.h"
#if defined(PSCAL_TARGET_IOS)
#if defined(__has_include)
#  if __has_include("PSCALRuntime.h")
#    include "PSCALRuntime.h"
#  else
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak_import));
#  endif
#elif defined(__APPLE__)
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak_import));
#else
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak));
#endif
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
#endif

int pscal_openssh_ssh_main(int argc, char **argv);
int pscal_openssh_scp_main(int argc, char **argv);
int pscal_openssh_sftp_main(int argc, char **argv);
int pscal_openssh_ssh_keygen_main(int argc, char **argv);
void PSCALRuntimeSetDebugLogMirroring(int enable);
__attribute__((weak)) void PSCALRuntimeSetDebugLogMirroring(int enable) { (void)enable; }
void PSCALRuntimeBeginScriptCapture(const char *path, int append) __attribute__((weak));
void PSCALRuntimeEndScriptCapture(void) __attribute__((weak));
int PSCALRuntimeScriptCaptureActive(void) __attribute__((weak));

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

static int smallclueInvokeOpensshEntry(const char *label, int (*entry)(int, char **),
                                       int argc, char **argv) {
    g_smallclue_openssh_exit_requested = 0;
    if (!entry) {
        fprintf(stderr, "%s: command unavailable\n", label ? label : "ssh");
        return 127;
    }
    pscal_openssh_exit_context exitContext;
    pscal_openssh_reset_progress_state();
    pscal_openssh_push_exit_context(&exitContext);
    PSCALRuntimeSetDebugLogMirroring(1);
    int status;
    if (sigsetjmp(exitContext.env, 0) == 0) {
        status = entry(argc, argv);
    } else {
        status = exitContext.exit_code;
    }
    PSCALRuntimeSetDebugLogMirroring(0);
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
} smallclueOpensshThreadContext;

static void *smallclueRunOpensshEntryThread(void *arg) {
    smallclueOpensshThreadContext *ctx = (smallclueOpensshThreadContext *)arg;
    int status = smallclueRunOpensshEntryOnce(ctx->label, ctx->entry, ctx->argc, ctx->argv);
    return (void *)(intptr_t)status;
}

static int smallclueRunOpensshEntry(const char *label, int (*entry)(int, char **),
                                    int argc, char **argv) {
    smallclueOpensshThreadContext ctx = {
        .label = label,
        .entry = entry,
        .argc = argc,
        .argv = argv
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
#else
static int smallclueRunOpensshEntry(const char *label, int (*entry)(int, char **),
                                    int argc, char **argv) {
    return smallclueRunOpensshEntryOnce(label, entry, argc, argv);
}
#endif

int smallclueRunSsh(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    if (argc < 2) {
        fprintf(stderr, "usage: ssh [options] host [command]\n");
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
        return smallclueRunOpensshEntry("ssh", pscal_openssh_ssh_main, argc, argv);
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

    int status = smallclueRunOpensshEntry("ssh", pscal_openssh_ssh_main, count, augmented);
    smallclueFreeArgv(augmented, count);
    return status;
}

int smallclueRunScp(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    return smallclueRunOpensshEntry("scp", pscal_openssh_scp_main, argc, argv);
}

int smallclueRunSftp(int argc, char **argv) {
    smallclueEnsureWritableHomeSsh();
    return smallclueRunOpensshEntry("sftp", pscal_openssh_sftp_main, argc, argv);
}

int smallclueRunSshKeygen(int argc, char **argv) {
    return smallclueRunOpensshEntry("ssh-keygen", pscal_openssh_ssh_keygen_main, argc, argv);
}
