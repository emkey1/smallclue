#include "micro_app.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include "termios_shim.h"
#if defined(PSCAL_TARGET_IOS)
#if defined(__has_include)
#if __has_include(<util.h>)
#include <util.h>
#define PSCAL_MICRO_HAS_OPENPTY 1
#elif __has_include(<pty.h>)
#include <pty.h>
#define PSCAL_MICRO_HAS_OPENPTY 1
#endif
#endif
#include "ios/vproc.h"
#include "ios/tty/pscal_tty.h"
typedef struct PSCALRuntimeContext PSCALRuntimeContext;
extern uint64_t PSCALRuntimeCurrentSessionId(void) __attribute__((weak_import));
extern VProcSessionStdio *PSCALRuntimeGetCurrentRuntimeStdio(void) __attribute__((weak_import));
extern int pscal_micro_go_notify_resize(uint64_t session_id, int cols, int rows) __attribute__((weak_import));
#endif

typedef struct {
    char *savedTerm;
    char *savedHome;
    char *savedXdgConfigHome;
    char *savedMicroConfigHome;
    char *savedTcellUseStdio;
    char *savedTcellAllowNonRaw;
} MicroEnvBackup;

typedef struct {
    int saved_fds[3];
    bool saved_valid[3];
} MicroStdFdBackup;

#if defined(PSCAL_TARGET_IOS)
typedef struct {
    uint64_t session_id;
    int tcell_stdin_fd;
    int tcell_stdout_fd;
} MicroGoLaunchContext;

static pthread_once_t gMicroGoLaunchCtxKeyOnce = PTHREAD_ONCE_INIT;
static pthread_key_t gMicroGoLaunchCtxKey;

static void microGoLaunchContextDestroy(void *opaque) {
    free(opaque);
}

static void microGoLaunchContextEnsureKey(void) {
    (void)pthread_key_create(&gMicroGoLaunchCtxKey, microGoLaunchContextDestroy);
}

static MicroGoLaunchContext *microGoLaunchContextGet(void) {
    (void)pthread_once(&gMicroGoLaunchCtxKeyOnce, microGoLaunchContextEnsureKey);
    return (MicroGoLaunchContext *)pthread_getspecific(gMicroGoLaunchCtxKey);
}

static void microGoLaunchContextSet(uint64_t session_id, int stdin_fd, int stdout_fd) {
    (void)pthread_once(&gMicroGoLaunchCtxKeyOnce, microGoLaunchContextEnsureKey);
    MicroGoLaunchContext *ctx = (MicroGoLaunchContext *)pthread_getspecific(gMicroGoLaunchCtxKey);
    if (!ctx) {
        ctx = (MicroGoLaunchContext *)calloc(1, sizeof(*ctx));
        if (!ctx) {
            return;
        }
        (void)pthread_setspecific(gMicroGoLaunchCtxKey, ctx);
    }
    ctx->session_id = session_id;
    ctx->tcell_stdin_fd = stdin_fd;
    ctx->tcell_stdout_fd = stdout_fd;
}

static void microGoLaunchContextClear(void) {
    MicroGoLaunchContext *ctx = microGoLaunchContextGet();
    if (!ctx) {
        return;
    }
    ctx->session_id = 0;
    ctx->tcell_stdin_fd = -1;
    ctx->tcell_stdout_fd = -1;
}

uint64_t pscal_micro_current_session_id(void) {
    MicroGoLaunchContext *ctx = microGoLaunchContextGet();
    if (!ctx) {
        return 0;
    }
    return ctx->session_id;
}

int pscal_micro_current_stdio_fds(int *stdin_fd, int *stdout_fd) {
    if (!stdin_fd || !stdout_fd) {
        return 0;
    }
    MicroGoLaunchContext *ctx = microGoLaunchContextGet();
    if (!ctx || ctx->tcell_stdin_fd < 0 || ctx->tcell_stdout_fd < 0) {
        return 0;
    }
    *stdin_fd = ctx->tcell_stdin_fd;
    *stdout_fd = ctx->tcell_stdout_fd;
    return 1;
}
#endif

static char *microDupEnv(const char *name) {
    const char *value = getenv(name);
    if (!value) {
        return NULL;
    }
    return strdup(value);
}

static void microRestoreEnvVar(const char *name, char *savedValue) {
    if (!name) {
        return;
    }
    if (savedValue) {
        setenv(name, savedValue, 1);
    } else {
        unsetenv(name);
    }
}

static void microEnsureDir(const char *path) {
    if (!path || !*path) {
        return;
    }
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return;
    }
}

static bool microDebugEnabled(void) {
    const char *toolDebug = getenv("PSCALI_TOOL_DEBUG");
    if (toolDebug && *toolDebug && strcmp(toolDebug, "0") != 0) {
        return true;
    }
    const char *microDebug = getenv("PSCALI_MICRO_DEBUG");
    if (microDebug && *microDebug && strcmp(microDebug, "0") != 0) {
        return true;
    }
    return false;
}

static bool microResizeTraceEnabled(void) {
    static int cached = -1;
    if (cached >= 0) {
        return cached == 1;
    }
    const char *traceEnv = getenv("PSCALI_MICRO_RESIZE_TRACE");
    if (traceEnv && *traceEnv) {
        cached = (strcmp(traceEnv, "0") != 0) ? 1 : 0;
        return cached == 1;
    }
    cached = 0;
    return cached == 1;
}

static void microResizeTracef(const char *format, ...) {
    if (!microResizeTraceEnabled() || !format) {
        return;
    }
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
}

static void microPrepareEnvironment(MicroEnvBackup *backup) {
    if (!backup) {
        return;
    }
    memset(backup, 0, sizeof(*backup));
    backup->savedTerm = microDupEnv("TERM");
    backup->savedHome = microDupEnv("HOME");
    backup->savedXdgConfigHome = microDupEnv("XDG_CONFIG_HOME");
    backup->savedMicroConfigHome = microDupEnv("MICRO_CONFIG_HOME");
    backup->savedTcellUseStdio = microDupEnv("PSCALI_TCELL_USE_STDIO");
    backup->savedTcellAllowNonRaw = microDupEnv("PSCALI_TCELL_ALLOW_NONRAW");

    setenv("TERM", "xterm-256color", 1);
    setenv("PSCALI_TCELL_USE_STDIO", "1", 1);
    setenv("PSCALI_TCELL_ALLOW_NONRAW", "0", 1);
    if (!getenv("PSCAL_MICRO_EMBEDDED")) {
        setenv("PSCAL_MICRO_EMBEDDED", "1", 1);
    }
    if (!getenv("PSCAL_MICRO_ENV_RESIZE_POLL")) {
        /* Resize is delivered per-session via C->Go callback in embedded mode.
         * Keep env polling disabled by default to avoid cross-instance env races. */
        setenv("PSCAL_MICRO_ENV_RESIZE_POLL", "0", 1);
    }

#if defined(PSCAL_TARGET_IOS)
    char resolvedWorkdir[PATH_MAX];
    resolvedWorkdir[0] = '\0';
    const char *workdir = NULL;
    const char *containerRoot = getenv("PSCALI_CONTAINER_ROOT");
    if (containerRoot && containerRoot[0] == '/') {
        int wn = snprintf(resolvedWorkdir, sizeof(resolvedWorkdir), "%s/Documents/home", containerRoot);
        if (wn > 0 && (size_t)wn < sizeof(resolvedWorkdir)) {
            workdir = resolvedWorkdir;
        }
    }
    if (!workdir || workdir[0] == '\0') {
        workdir = getenv("PSCALI_WORKDIR");
    }
    if (workdir && workdir[0] == '/') {
        microEnsureDir(workdir);
        setenv("PSCALI_WORKDIR", workdir, 1);
        setenv("HOME", workdir, 1);
        char configPath[PATH_MAX];
        int n = snprintf(configPath, sizeof(configPath), "%s/.config", workdir);
        if (n > 0 && (size_t)n < sizeof(configPath)) {
            setenv("XDG_CONFIG_HOME", configPath, 1);
            microEnsureDir(configPath);
            char microConfigPath[PATH_MAX];
            int mn = snprintf(microConfigPath, sizeof(microConfigPath), "%s/micro", configPath);
            if (mn > 0 && (size_t)mn < sizeof(microConfigPath)) {
                setenv("MICRO_CONFIG_HOME", microConfigPath, 1);
                microEnsureDir(microConfigPath);
            }
        }
    }
#endif
}

static void microRestoreEnvironment(MicroEnvBackup *backup) {
    if (!backup) {
        return;
    }
    microRestoreEnvVar("TERM", backup->savedTerm);
    microRestoreEnvVar("HOME", backup->savedHome);
    microRestoreEnvVar("XDG_CONFIG_HOME", backup->savedXdgConfigHome);
    microRestoreEnvVar("MICRO_CONFIG_HOME", backup->savedMicroConfigHome);
    microRestoreEnvVar("PSCALI_TCELL_USE_STDIO", backup->savedTcellUseStdio);
    microRestoreEnvVar("PSCALI_TCELL_ALLOW_NONRAW", backup->savedTcellAllowNonRaw);
    free(backup->savedTerm);
    free(backup->savedHome);
    free(backup->savedXdgConfigHome);
    free(backup->savedMicroConfigHome);
    free(backup->savedTcellUseStdio);
    free(backup->savedTcellAllowNonRaw);
    memset(backup, 0, sizeof(*backup));
}

static bool microArgvHasConfigDir(int argc, char **argv) {
    if (argc <= 1 || !argv) {
        return false;
    }
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-config-dir") == 0) {
            return true;
        }
        if (strncmp(arg, "-config-dir=", 12) == 0) {
            return true;
        }
    }
    return false;
}

static char **microInjectConfigDirArgv(int argc, char **argv, const char *configDir, int *outArgc) {
    if (outArgc) {
        *outArgc = argc;
    }
    if (argc <= 0 || !argv || !configDir || configDir[0] == '\0' || microArgvHasConfigDir(argc, argv)) {
        return NULL;
    }
    char **patched = (char **)calloc((size_t)argc + 3u, sizeof(char *));
    if (!patched) {
        return NULL;
    }
    int dst = 0;
    patched[dst++] = argv[0];
    patched[dst++] = "-config-dir";
    patched[dst++] = (char *)configDir;
    for (int src = 1; src < argc; ++src) {
        patched[dst++] = argv[src];
    }
    patched[dst] = NULL;
    if (outArgc) {
        *outArgc = dst;
    }
    return patched;
}

static void microSaveStandardFds(MicroStdFdBackup *backup) {
    if (!backup) {
        return;
    }
    memset(backup, 0, sizeof(*backup));
    int targets[3] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
    for (int i = 0; i < 3; ++i) {
        int fd = dup(targets[i]);
        if (fd >= 0) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            backup->saved_fds[i] = fd;
            backup->saved_valid[i] = true;
        } else {
            backup->saved_fds[i] = -1;
            backup->saved_valid[i] = false;
        }
    }
}

static void microRestoreStandardFds(MicroStdFdBackup *backup) {
    if (!backup) {
        return;
    }
    int targets[3] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
    for (int i = 0; i < 3; ++i) {
        if (!backup->saved_valid[i] || backup->saved_fds[i] < 0) {
            continue;
        }
        (void)dup2(backup->saved_fds[i], targets[i]);
        close(backup->saved_fds[i]);
        backup->saved_fds[i] = -1;
        backup->saved_valid[i] = false;
    }
}

#if defined(PSCAL_TARGET_IOS)
static pthread_mutex_t gMicroBridgeStateMu = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    uint64_t session_id;
    int pty_master;
    int pty_slave;
    bool pty_use_shim;
    pthread_t main_thread;
    bool main_thread_valid;
} MicroBridgeSessionState;
static MicroBridgeSessionState *gMicroBridgeStates = NULL;
static size_t gMicroBridgeStateCount = 0;
static size_t gMicroBridgeStateCapacity = 0;

static ssize_t microBridgeStateFindIndexLocked(uint64_t session_id) {
    if (session_id == 0) {
        return -1;
    }
    for (size_t i = 0; i < gMicroBridgeStateCount; ++i) {
        if (gMicroBridgeStates[i].session_id == session_id) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static int microBridgeStateEnsureCapacityLocked(size_t needed) {
    if (needed <= gMicroBridgeStateCapacity) {
        return 0;
    }
    size_t new_cap = gMicroBridgeStateCapacity == 0 ? 4 : gMicroBridgeStateCapacity * 2;
    while (new_cap < needed) {
        new_cap *= 2;
    }
    MicroBridgeSessionState *resized = (MicroBridgeSessionState *)realloc(
        gMicroBridgeStates, new_cap * sizeof(*resized));
    if (!resized) {
        return -1;
    }
    memset(resized + gMicroBridgeStateCapacity,
           0,
           (new_cap - gMicroBridgeStateCapacity) * sizeof(*resized));
    gMicroBridgeStates = resized;
    gMicroBridgeStateCapacity = new_cap;
    return 0;
}

static void microBridgeStateRemoveIndexLocked(size_t idx) {
    if (idx >= gMicroBridgeStateCount) {
        return;
    }
    if (idx + 1 < gMicroBridgeStateCount) {
        gMicroBridgeStates[idx] = gMicroBridgeStates[gMicroBridgeStateCount - 1];
    }
    gMicroBridgeStateCount--;
}

static MicroBridgeSessionState *microBridgeStateGetOrCreateLocked(uint64_t session_id) {
    if (session_id == 0) {
        return NULL;
    }
    ssize_t idx = microBridgeStateFindIndexLocked(session_id);
    if (idx >= 0) {
        return &gMicroBridgeStates[idx];
    }
    if (microBridgeStateEnsureCapacityLocked(gMicroBridgeStateCount + 1) != 0) {
        return NULL;
    }
    MicroBridgeSessionState *entry = &gMicroBridgeStates[gMicroBridgeStateCount++];
    memset(entry, 0, sizeof(*entry));
    entry->session_id = session_id;
    entry->pty_master = -1;
    entry->pty_slave = -1;
    return entry;
}

static void microBridgeStateSet(uint64_t session_id,
                                int pty_master,
                                int pty_slave,
                                bool pty_use_shim) {
    if (session_id == 0) {
        return;
    }
    pthread_mutex_lock(&gMicroBridgeStateMu);
    MicroBridgeSessionState *entry = microBridgeStateGetOrCreateLocked(session_id);
    if (entry) {
        entry->pty_master = pty_master;
        entry->pty_slave = pty_slave;
        entry->pty_use_shim = pty_use_shim;
        if (!entry->main_thread_valid &&
            entry->pty_master < 0 &&
            entry->pty_slave < 0) {
            ssize_t idx = microBridgeStateFindIndexLocked(session_id);
            if (idx >= 0) {
                microBridgeStateRemoveIndexLocked((size_t)idx);
            }
        }
    }
    microResizeTracef("[micro-resize] micro bridgeStateSet session=%llu pty_master=%d pty_slave=%d shim=%d",
                      (unsigned long long)session_id,
                      pty_master,
                      pty_slave,
                      pty_use_shim ? 1 : 0);
    pthread_mutex_unlock(&gMicroBridgeStateMu);
}

static void microBridgeMainThreadSet(uint64_t session_id, pthread_t tid, bool valid) {
    if (session_id == 0) {
        return;
    }
    pthread_mutex_lock(&gMicroBridgeStateMu);
    MicroBridgeSessionState *entry = microBridgeStateGetOrCreateLocked(session_id);
    if (entry) {
        entry->main_thread = tid;
        entry->main_thread_valid = valid;
        if (!entry->main_thread_valid &&
            entry->pty_master < 0 &&
            entry->pty_slave < 0) {
            ssize_t idx = microBridgeStateFindIndexLocked(session_id);
            if (idx >= 0) {
                microBridgeStateRemoveIndexLocked((size_t)idx);
            }
        }
    }
    pthread_mutex_unlock(&gMicroBridgeStateMu);
}

static void microUpdateSizeEnv(int cols, int rows) {
    char buf[16];
    if (cols > 0) {
        int n = snprintf(buf, sizeof(buf), "%d", cols);
        if (n > 0) {
            setenv("COLUMNS", buf, 1);
        }
    }
    if (rows > 0) {
        int n = snprintf(buf, sizeof(buf), "%d", rows);
        if (n > 0) {
            setenv("LINES", buf, 1);
        }
    }
}

static bool microNotifyGoResize(uint64_t session_id, int cols, int rows) {
    if (session_id == 0 || cols <= 0 || rows <= 0) {
        return false;
    }
    if (!pscal_micro_go_notify_resize) {
        return false;
    }
    return pscal_micro_go_notify_resize(session_id, cols, rows) != 0;
}

static int microParsePositiveEnvInt(const char *name) {
    if (!name || !*name) {
        return 0;
    }
    const char *value = getenv(name);
    if (!value || !*value) {
        return 0;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || (end && *end != '\0') || parsed <= 0 || parsed > 1000) {
        return 0;
    }
    return (int)parsed;
}

static bool microProbeWinsizeFd(int fd, int *cols_out, int *rows_out) {
    if (fd < 0 || !cols_out || !rows_out) {
        return false;
    }
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    if (ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        *cols_out = (int)ws.ws_col;
        *rows_out = (int)ws.ws_row;
        return true;
    }
#if defined(PSCAL_TARGET_IOS)
    if (vprocCurrent()) {
        memset(&ws, 0, sizeof(ws));
        if (vprocIoctlShim(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
            *cols_out = (int)ws.ws_col;
            *rows_out = (int)ws.ws_row;
            return true;
        }
    }
#endif
    return false;
}

static bool microProbeWinsizeSessionStdio(const VProcSessionStdio *session_stdio,
                                          int *cols_out,
                                          int *rows_out,
                                          const char **source_out) {
    if (!session_stdio || !cols_out || !rows_out) {
        return false;
    }
    if (microProbeWinsizeFd(session_stdio->stdout_host_fd, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "session-stdout";
        }
        return true;
    }
    if (microProbeWinsizeFd(session_stdio->stdin_host_fd, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "session-stdin";
        }
        return true;
    }
    if (microProbeWinsizeFd(session_stdio->stderr_host_fd, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "session-stderr";
        }
        return true;
    }
    return false;
}

static bool microResolveLaunchWinsize(uint64_t session_id,
                                      const VProcSessionStdio *session_stdio,
                                      int *cols_out,
                                      int *rows_out,
                                      const char **source_out) {
    if (!cols_out || !rows_out) {
        return false;
    }
    *cols_out = 0;
    *rows_out = 0;
    if (source_out) {
        *source_out = "none";
    }

    if (microProbeWinsizeSessionStdio(session_stdio, cols_out, rows_out, source_out)) {
        return true;
    }

    if (microProbeWinsizeFd(STDOUT_FILENO, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "stdout";
        }
        return true;
    }
    if (microProbeWinsizeFd(STDIN_FILENO, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "stdin";
        }
        return true;
    }
    if (microProbeWinsizeFd(STDERR_FILENO, cols_out, rows_out)) {
        if (source_out) {
            *source_out = "stderr";
        }
        return true;
    }
    if (session_id != 0) {
        /* Runtime/session binding can lag slightly behind command launch on iOS.
         * Retry briefly so startup geometry reflects the active terminal. */
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (vprocGetSessionWinsize(session_id, cols_out, rows_out) == 0 &&
                *cols_out > 0 &&
                *rows_out > 0) {
                if (source_out) {
                    *source_out = "session";
                }
                return true;
            }
            if (attempt < 7) {
                usleep(25000);
            }
        }
    }

    int env_cols = microParsePositiveEnvInt("COLUMNS");
    int env_rows = microParsePositiveEnvInt("LINES");
    if (env_cols > 0 && env_rows > 0) {
        *cols_out = env_cols;
        *rows_out = env_rows;
        if (source_out) {
            *source_out = "env";
        }
        return true;
    }

    return false;
}

static void microApplyBridgeWinsizeLocked(uint64_t session_id,
                                          int pty_master,
                                          int pty_slave,
                                          bool use_shim_ioctl,
                                          int cols,
                                          int rows) {
    if (cols <= 0 || rows <= 0) {
        return;
    }
    if (pty_master >= 0 || pty_slave >= 0) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_col = (unsigned short)cols;
        ws.ws_row = (unsigned short)rows;
        if (use_shim_ioctl) {
            if (vprocCurrent()) {
                if (pty_slave >= 0) {
                    (void)vprocIoctlShim(pty_slave, TIOCSWINSZ, &ws);
                }
                if (pty_master >= 0) {
                    (void)vprocIoctlShim(pty_master, TIOCSWINSZ, &ws);
                }
            }
        } else {
            if (pty_slave >= 0) {
                (void)ioctl(pty_slave, TIOCSWINSZ, &ws);
            }
            if (pty_master >= 0) {
                (void)ioctl(pty_master, TIOCSWINSZ, &ws);
            }
        }
    }
    if (pty_master < 0 && pty_slave < 0 && !microNotifyGoResize(session_id, cols, rows)) {
        /* Pipe relay fallback: keep env as backward-compatible resize path. */
        microUpdateSizeEnv(cols, rows);
    }
    microResizeTracef("[micro-resize] micro applyBridgeWinsize pty_master=%d pty_slave=%d cols=%d rows=%d shim=%d",
                      pty_master,
                      pty_slave,
                      cols,
                      rows,
                      use_shim_ioctl ? 1 : 0);
}

static void microSignalResizeLocked(pthread_t thread, bool thread_valid) {
#ifdef SIGWINCH
    if (thread_valid) {
        int rc = pthread_kill(thread, SIGWINCH);
        if (rc != 0) {
            microResizeTracef("[micro-resize] micro signalResize sig=SIGWINCH rc=%d", rc);
        }
    }
#endif
}

void pscalMicroNotifySessionWinsize(uint64_t session_id, int cols, int rows) {
    static int miss_log_budget = 24;
    if (session_id == 0 || cols <= 0 || rows <= 0) {
        return;
    }
    pthread_mutex_lock(&gMicroBridgeStateMu);
    ssize_t idx = microBridgeStateFindIndexLocked(session_id);
    bool match = (idx >= 0);
    int pty_master = -1;
    int pty_slave = -1;
    bool pty_use_shim = false;
    pthread_t main_thread = (pthread_t)0;
    bool main_thread_valid = false;
    if (match) {
        MicroBridgeSessionState *entry = &gMicroBridgeStates[idx];
        pty_master = entry->pty_master;
        pty_slave = entry->pty_slave;
        pty_use_shim = entry->pty_use_shim;
        main_thread = entry->main_thread;
        main_thread_valid = entry->main_thread_valid;
    }
    if (match || miss_log_budget > 0) {
        microResizeTracef("[micro-resize] micro notifySessionWinsize session=%llu cols=%d rows=%d match=%d pty_master=%d pty_slave=%d shim=%d",
                          (unsigned long long)session_id,
                          cols,
                          rows,
                          match ? 1 : 0,
                          pty_master,
                          pty_slave,
                          pty_use_shim ? 1 : 0);
        if (!match && miss_log_budget > 0) {
            miss_log_budget--;
        }
    }
    if (match) {
        microApplyBridgeWinsizeLocked(session_id, pty_master, pty_slave, pty_use_shim, cols, rows);
        microSignalResizeLocked(main_thread, main_thread_valid);
    }
    pthread_mutex_unlock(&gMicroBridgeStateMu);
}

typedef struct {
    int read_fd;
    int write_fd;
    bool read_host;
    bool read_vproc_shim;
    bool write_host;
    bool write_vproc_shim;
    bool write_session_output;
    bool read_session_input;
    bool read_nonblocking;
    uint64_t session_id;
    VProc *vp;
    VProcSessionStdio *session_stdio;
    volatile sig_atomic_t *stop_requested;
} MicroIoBridgeThreadCtx;

typedef struct {
    bool active;
    int saved_host_stdin;
    int saved_host_stdout;
    int saved_host_stderr;
    uint64_t session_id;
    int pty_master;
    int pty_slave;
    bool pty_use_shim;
    bool pipe_stdio_mode;
    bool stdio_redirected;
    int stdin_pipe_read;
    int stdin_pipe_write;
    int output_pipe_read;
    int output_pipe_write;
    VProc *vp;
    VProcSessionStdio *session_stdio;
    pthread_t stdin_thread;
    pthread_t output_thread;
    pthread_t output_host_thread;
    pthread_t resize_thread;
    bool stdin_thread_started;
    bool output_thread_started;
    bool output_host_thread_started;
    bool resize_thread_started;
    int last_cols;
    int last_rows;
    volatile sig_atomic_t stop_requested;
    MicroIoBridgeThreadCtx stdin_ctx;
    MicroIoBridgeThreadCtx output_ctx;
    MicroIoBridgeThreadCtx output_host_ctx;
} MicroHostStdioBridge;

static void microHostStdioBridgeTeardown(MicroHostStdioBridge *bridge);

static void microHostStdioBridgeInit(MicroHostStdioBridge *bridge) {
    if (!bridge) {
        return;
    }
    memset(bridge, 0, sizeof(*bridge));
    bridge->saved_host_stdin = -1;
    bridge->saved_host_stdout = -1;
    bridge->saved_host_stderr = -1;
    bridge->session_id = 0;
    bridge->pty_master = -1;
    bridge->pty_slave = -1;
    bridge->pty_use_shim = false;
    bridge->pipe_stdio_mode = false;
    bridge->stdio_redirected = false;
    bridge->stdin_pipe_read = -1;
    bridge->stdin_pipe_write = -1;
    bridge->output_pipe_read = -1;
    bridge->output_pipe_write = -1;
    bridge->vp = NULL;
    bridge->last_cols = -1;
    bridge->last_rows = -1;
    bridge->stop_requested = 0;
}

static void microCloseIfOpen(int *fd, bool use_shim_close) {
    if (!fd || *fd < 0) {
        return;
    }
    if (use_shim_close) {
        (void)vprocCloseShim(*fd);
    } else {
        (void)vprocHostClose(*fd);
    }
    *fd = -1;
}

static ssize_t microIoBridgeRead(const MicroIoBridgeThreadCtx *ctx,
                                 void *buf,
                                 size_t count) {
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }
    if (ctx->read_session_input) {
        return vprocSessionReadInputShimMode(buf, count, ctx->read_nonblocking);
    }
    if (ctx->read_host) {
        return vprocHostRead(ctx->read_fd, buf, count);
    }
    if (ctx->read_vproc_shim) {
        return vprocReadShim(ctx->read_fd, buf, count);
    }
    return read(ctx->read_fd, buf, count);
}

static ssize_t microIoBridgeWrite(const MicroIoBridgeThreadCtx *ctx,
                                  const void *buf,
                                  size_t count) {
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }
    if (ctx->write_host) {
        return vprocHostWrite(ctx->write_fd, buf, count);
    }
    if (ctx->write_vproc_shim) {
        return vprocWriteShim(ctx->write_fd, buf, count);
    }
    if (ctx->write_session_output) {
        ssize_t out = vprocSessionEmitOutput(ctx->session_id, buf, count);
        if (out >= 0) {
            return out;
        }
        return -1;
    }
    return write(ctx->write_fd, buf, count);
}

static void *microIoBridgeThreadMain(void *opaque) {
    MicroIoBridgeThreadCtx *ctx = (MicroIoBridgeThreadCtx *)opaque;
    VProcSessionStdio *prev_stdio = NULL;
    bool vproc_active = false;
    bool have_read = false;
    bool have_write = false;
    const char *exit_reason = "unknown";
    int exit_errno = 0;
    if (!ctx) {
        return NULL;
    }
    if (ctx->vp) {
        vprocActivate(ctx->vp);
        vprocRegisterThread(ctx->vp, pthread_self());
        vproc_active = true;
    }
    if (ctx->session_stdio) {
        prev_stdio = vprocSessionStdioCurrent();
        vprocSessionStdioActivate(ctx->session_stdio);
    }
    have_read = ctx->read_session_input || ctx->read_fd >= 0;
    have_write = ctx->write_session_output || ctx->write_fd >= 0;
    if (!have_read || !have_write) {
        exit_reason = "invalid-endpoint";
        goto cleanup;
    }
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    unsigned char buf[4096];
    for (;;) {
        if (ctx->stop_requested && *ctx->stop_requested) {
            exit_reason = "stop-requested";
            break;
        }
        ssize_t nr = microIoBridgeRead(ctx, buf, sizeof(buf));
        if (nr < 0 && ctx->read_nonblocking &&
            (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) {
            usleep(10000);
            continue;
        }
        if (nr < 0) {
            exit_reason = "read-error";
            exit_errno = errno;
            break;
        }
        if (nr == 0) {
            exit_reason = "read-eof";
            break;
        }
        size_t off = 0;
        while (off < (size_t)nr) {
            ssize_t nw = microIoBridgeWrite(ctx, buf + off, (size_t)nr - off);
            if (nw <= 0) {
                exit_reason = (nw < 0) ? "write-error" : "write-zero";
                exit_errno = (nw < 0) ? errno : 0;
                goto cleanup;
            }
            off += (size_t)nw;
        }
    }
cleanup:
    microResizeTracef("[micro-resize] micro ioBridgeThread exit reason=%s errno=%d read_fd=%d write_fd=%d read_session=%d write_session=%d read_host=%d read_shim=%d write_host=%d write_shim=%d session=%llu",
                      exit_reason,
                      exit_errno,
                      ctx->read_fd,
                      ctx->write_fd,
                      ctx->read_session_input ? 1 : 0,
                      ctx->write_session_output ? 1 : 0,
                      ctx->read_host ? 1 : 0,
                      ctx->read_vproc_shim ? 1 : 0,
                      ctx->write_host ? 1 : 0,
                      ctx->write_vproc_shim ? 1 : 0,
                      (unsigned long long)ctx->session_id);
    if (ctx->session_stdio) {
        vprocSessionStdioActivate(prev_stdio);
    }
    if (vproc_active) {
        vprocUnregisterThread(ctx->vp, pthread_self());
        vprocDeactivate();
    }
    return NULL;
}

static bool microBridgeApplySessionWinsize(MicroHostStdioBridge *bridge,
                                           bool force,
                                           bool signal_resize) {
    if (!bridge || bridge->session_id == 0) {
        return false;
    }
    int cols = 0;
    int rows = 0;
    if (vprocGetSessionWinsize(bridge->session_id, &cols, &rows) != 0 ||
        cols <= 0 ||
        rows <= 0) {
        microResizeTracef("[micro-resize] micro bridgeApplySessionWinsize session=%llu force=%d signal=%d unavailable",
                          (unsigned long long)bridge->session_id,
                          force ? 1 : 0,
                          signal_resize ? 1 : 0);
        return false;
    }
    if (!force && cols == bridge->last_cols && rows == bridge->last_rows) {
        return true;
    }
    pthread_mutex_lock(&gMicroBridgeStateMu);
    pthread_t main_thread = (pthread_t)0;
    bool main_thread_valid = false;
    ssize_t idx = microBridgeStateFindIndexLocked(bridge->session_id);
    if (idx >= 0) {
        main_thread = gMicroBridgeStates[idx].main_thread;
        main_thread_valid = gMicroBridgeStates[idx].main_thread_valid;
    }
    microApplyBridgeWinsizeLocked(bridge->session_id,
                                  bridge->pty_master,
                                  bridge->pty_slave,
                                  bridge->pty_use_shim,
                                  cols,
                                  rows);
    if (signal_resize) {
        microSignalResizeLocked(main_thread, main_thread_valid);
    }
    pthread_mutex_unlock(&gMicroBridgeStateMu);
    bridge->last_cols = cols;
    bridge->last_rows = rows;
    microResizeTracef("[micro-resize] micro bridgeApplySessionWinsize session=%llu force=%d signal=%d applied=%dx%d",
                      (unsigned long long)bridge->session_id,
                      force ? 1 : 0,
                      signal_resize ? 1 : 0,
                      cols,
                      rows);
    return true;
}

static void *microBridgeResizeThreadMain(void *opaque) {
    MicroHostStdioBridge *bridge = (MicroHostStdioBridge *)opaque;
    bool vproc_active = false;
    if (!bridge) {
        return NULL;
    }
    if (bridge->pty_use_shim && bridge->vp) {
        vprocActivate(bridge->vp);
        vprocRegisterThread(bridge->vp, pthread_self());
        vproc_active = true;
    }
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    while (!bridge->stop_requested) {
        (void)microBridgeApplySessionWinsize(bridge, false, true);
        usleep(150000);
    }
    if (vproc_active) {
        vprocUnregisterThread(bridge->vp, pthread_self());
        vprocDeactivate();
    }
    return NULL;
}

static bool microBridgeTryShimPty(MicroHostStdioBridge *bridge, int host_ptmx_errno) {
    if (!bridge) {
        return false;
    }
    const char *allow_shim_env = getenv("PSCALI_MICRO_ALLOW_SHIM_PTY");
    /* iOS should use vproc virtual PTYs by default. Allow disabling
     * only for targeted diagnostics with PSCALI_MICRO_ALLOW_SHIM_PTY=0. */
    bool allow_shim = true;
    if (allow_shim_env && strcmp(allow_shim_env, "0") == 0) {
        allow_shim = false;
    }
    if (!allow_shim) {
        if (microDebugEnabled()) {
            fprintf(stderr,
                    "[micro-bridge] shim PTY disabled (host errno=%d)\n",
                    host_ptmx_errno);
        }
        return false;
    }

    int pty_num = -1;
    int unlocked = 0;
    char pty_slave_name[64];

    bridge->pty_master = vprocOpenShim("/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if (bridge->pty_master < 0) {
        if (microDebugEnabled()) {
            fprintf(stderr,
                    "[micro-bridge] shim PTY unavailable: host errno=%d shim errno=%d\n",
                    host_ptmx_errno,
                    errno);
        }
        return false;
    }

    bridge->pty_use_shim = true;
    bridge->vp = vprocCurrent();
    (void)vprocIoctlShim(bridge->pty_master, TIOCSPTLCK_, &unlocked);
    if (vprocIoctlShim(bridge->pty_master, TIOCGPTN_, &pty_num) != 0 || pty_num < 0) {
        microCloseIfOpen(&bridge->pty_master, true);
        bridge->pty_use_shim = false;
        bridge->vp = NULL;
        return false;
    }

    snprintf(pty_slave_name, sizeof(pty_slave_name), "/dev/pts/%d", pty_num);
    bridge->pty_slave = vprocOpenShim(pty_slave_name, O_RDWR | O_NOCTTY, 0);
    if (bridge->pty_slave < 0) {
        microCloseIfOpen(&bridge->pty_master, true);
        bridge->pty_use_shim = false;
        bridge->vp = NULL;
        return false;
    }

    return true;
}

static bool microHostStdioBridgeSetup(MicroHostStdioBridge *bridge,
                                      VProcSessionStdio *preferred_session_stdio,
                                      uint64_t preferred_session_id) {
    if (!bridge) {
        return false;
    }
    microHostStdioBridgeInit(bridge);

    bridge->saved_host_stdin = vprocHostDup(STDIN_FILENO);
    bridge->saved_host_stdout = vprocHostDup(STDOUT_FILENO);
    bridge->saved_host_stderr = vprocHostDup(STDERR_FILENO);

    if (bridge->saved_host_stdin < 0 || bridge->saved_host_stdout < 0 || bridge->saved_host_stderr < 0) {
        goto fail;
    }
    VProcSessionStdio *session_stdio = vprocSessionStdioCurrent();
    if ((!session_stdio || session_stdio->session_id == 0) &&
        preferred_session_stdio &&
        preferred_session_stdio->session_id != 0) {
        session_stdio = preferred_session_stdio;
    }
    if ((!session_stdio || session_stdio->session_id == 0) &&
        PSCALRuntimeGetCurrentRuntimeStdio) {
        VProcSessionStdio *runtime_stdio = PSCALRuntimeGetCurrentRuntimeStdio();
        if (runtime_stdio && runtime_stdio->session_id != 0) {
            session_stdio = runtime_stdio;
        }
    }
    uint64_t session_id = 0;
    if (session_stdio && session_stdio->session_id != 0) {
        session_id = session_stdio->session_id;
        vprocSessionStdioActivate(session_stdio);
    }
    if (session_id == 0 && preferred_session_id != 0) {
        session_id = preferred_session_id;
    }
    if (session_id == 0 && PSCALRuntimeCurrentSessionId) {
        session_id = PSCALRuntimeCurrentSessionId();
    }
    if (preferred_session_id != 0 && session_id != preferred_session_id) {
        microResizeTracef("[micro-resize] micro bridgeSetup session override resolved=%llu preferred=%llu",
                          (unsigned long long)session_id,
                          (unsigned long long)preferred_session_id);
        session_id = preferred_session_id;
        if (preferred_session_stdio &&
            preferred_session_stdio->session_id == preferred_session_id) {
            session_stdio = preferred_session_stdio;
            vprocSessionStdioActivate(session_stdio);
        }
    }
    if (session_id == 0) {
        microResizeTracef("[micro-resize] micro bridgeSetup missing-session preferred=%llu runtime_current=%llu",
                          (unsigned long long)preferred_session_id,
                          (unsigned long long)(PSCALRuntimeCurrentSessionId ? PSCALRuntimeCurrentSessionId() : 0));
        goto fail;
    }
    bridge->session_id = session_id;
    bridge->session_stdio = session_stdio;
    microResizeTracef("[micro-resize] micro bridgeSetup session=%llu session_stdio=%p preferred=%llu",
                      (unsigned long long)bridge->session_id,
                      (void *)bridge->session_stdio,
                      (unsigned long long)preferred_session_id);

    const char *force_pipe_env = getenv("PSCALI_MICRO_FORCE_PIPE");
    /* Keep pipe relay as default so all micro output stays on the active
     * terminal tab instead of leaking to host/Xcode console streams.
     * PTY-first mode can still be enabled for diagnostics with
     * PSCALI_MICRO_FORCE_PIPE=0. */
    bool force_pipe_stdio_mode = true;
    if (force_pipe_env && *force_pipe_env) {
        force_pipe_stdio_mode = (strcmp(force_pipe_env, "0") != 0);
    }
    int host_ptmx_errno = 0;
    const char *allow_host_pty_env = getenv("PSCALI_MICRO_ALLOW_HOST_PTY");
    /* Keep micro attached to vproc/session PTYs by default on iOS.
     * Enable host PTY fallback only for targeted diagnostics. */
    bool allow_host_pty_fallback = false;
    if (allow_host_pty_env && *allow_host_pty_env && strcmp(allow_host_pty_env, "0") != 0) {
        allow_host_pty_fallback = true;
    }
    if (!force_pipe_stdio_mode && !microBridgeTryShimPty(bridge, 0) && allow_host_pty_fallback) {
        bridge->pty_master = vprocHostOpen("/dev/ptmx", O_RDWR | O_NOCTTY, 0);
        if (bridge->pty_master < 0) {
            bridge->pty_master = vprocHostOpen("/private/dev/ptmx", O_RDWR | O_NOCTTY, 0);
        }
        if (bridge->pty_master < 0) {
            bridge->pty_master = vprocHostOpen("/dev/pts/ptmx", O_RDWR | O_NOCTTY, 0);
        }
        if (bridge->pty_master < 0) {
            bridge->pty_master = vprocHostOpen("/private/dev/pts/ptmx", O_RDWR | O_NOCTTY, 0);
        }
        if (bridge->pty_master >= 0) {
            char pty_slave_name[128];
            if (grantpt(bridge->pty_master) != 0 || unlockpt(bridge->pty_master) != 0) {
                goto fail;
            }
            if (ptsname_r(bridge->pty_master, pty_slave_name, sizeof(pty_slave_name)) != 0) {
                goto fail;
            }
            bridge->pty_slave = vprocHostOpen(pty_slave_name, O_RDWR | O_NOCTTY, 0);
            if (bridge->pty_slave < 0) {
                goto fail;
            }
        } else {
            host_ptmx_errno = errno;
#if defined(PSCAL_MICRO_HAS_OPENPTY)
            int openpty_master = -1;
            int openpty_slave = -1;
            if (openpty(&openpty_master, &openpty_slave, NULL, NULL, NULL) == 0) {
                bridge->pty_master = openpty_master;
                bridge->pty_slave = openpty_slave;
                if (microDebugEnabled()) {
                    fprintf(stderr,
                            "[micro-bridge] bridgeSetup host PTY allocated via openpty (ptmx errno=%d)\n",
                            host_ptmx_errno);
                }
            }
#endif
            if (bridge->pty_master < 0 || bridge->pty_slave < 0) {
                (void)microBridgeTryShimPty(bridge, host_ptmx_errno);
            }
        }
    } else if (!force_pipe_stdio_mode && !allow_host_pty_fallback && bridge->pty_master < 0) {
        if (microDebugEnabled()) {
            fprintf(stderr,
                    "[micro-bridge] host PTY fallback disabled; shim PTY required\n");
        }
    }

    if (force_pipe_stdio_mode) {
        bridge->pipe_stdio_mode = true;
        bridge->pty_master = -1;
        bridge->pty_slave = -1;
        bridge->pty_use_shim = false;
        bridge->vp = NULL;
    }

    if (bridge->pty_master < 0 || bridge->pty_slave < 0) {
        /* Last-resort mode: no PTY semantics, but keep I/O attached to
         * the active tab via host stdio capture pipes. */
        bridge->pipe_stdio_mode = true;
        bridge->pty_master = -1;
        bridge->pty_slave = -1;
        bridge->pty_use_shim = false;
        bridge->vp = NULL;
        if (microDebugEnabled()) {
            fprintf(stderr,
                    "[micro-bridge] bridgeSetup fallback to stdio-pipe relay only (ptmx errno=%d)\n",
                    host_ptmx_errno);
        }
    }

    if (bridge->pipe_stdio_mode) {
        int in_pipe[2] = { -1, -1 };
        int out_pipe[2] = { -1, -1 };
        if (vprocHostPipe(in_pipe) != 0 || vprocHostPipe(out_pipe) != 0) {
            if (in_pipe[0] >= 0) close(in_pipe[0]);
            if (in_pipe[1] >= 0) close(in_pipe[1]);
            if (out_pipe[0] >= 0) close(out_pipe[0]);
            if (out_pipe[1] >= 0) close(out_pipe[1]);
            goto fail;
        }
        bridge->stdin_pipe_read = in_pipe[0];
        bridge->stdin_pipe_write = in_pipe[1];
        bridge->output_pipe_read = out_pipe[0];
        bridge->output_pipe_write = out_pipe[1];
        fcntl(bridge->stdin_pipe_read, F_SETFD, FD_CLOEXEC);
        fcntl(bridge->stdin_pipe_write, F_SETFD, FD_CLOEXEC);
        fcntl(bridge->output_pipe_read, F_SETFD, FD_CLOEXEC);
        fcntl(bridge->output_pipe_write, F_SETFD, FD_CLOEXEC);
    }

    if (bridge->pty_use_shim) {
        if (vprocDup2Shim(bridge->pty_slave, STDIN_FILENO) < 0 ||
            vprocDup2Shim(bridge->pty_slave, STDOUT_FILENO) < 0 ||
            vprocDup2Shim(bridge->pty_slave, STDERR_FILENO) < 0) {
            goto fail;
        }
        bridge->stdio_redirected = true;
    } else if (bridge->pty_slave >= 0) {
        if (vprocHostDup2(bridge->pty_slave, STDIN_FILENO) < 0 ||
            vprocHostDup2(bridge->pty_slave, STDOUT_FILENO) < 0 ||
            vprocHostDup2(bridge->pty_slave, STDERR_FILENO) < 0) {
            goto fail;
        }
        bridge->stdio_redirected = true;
    }
    /* Seed initial size from the active session PTY when available. This is
     * more reliable than host stdout in embedded/iOS contexts. */
    if (!microBridgeApplySessionWinsize(bridge, true, false)) {
        int host_cols = 0;
        int host_rows = 0;
        const char *seed_source = "none";
        if (microProbeWinsizeSessionStdio(bridge->session_stdio, &host_cols, &host_rows, &seed_source)) {
            /* source already set by helper */
        } else if (microProbeWinsizeFd(bridge->saved_host_stdout, &host_cols, &host_rows)) {
            seed_source = "host-stdout";
        } else if (microProbeWinsizeFd(bridge->saved_host_stdin, &host_cols, &host_rows)) {
            seed_source = "host-stdin";
        } else if (microProbeWinsizeFd(bridge->saved_host_stderr, &host_cols, &host_rows)) {
            seed_source = "host-stderr";
        } else {
            host_cols = microParsePositiveEnvInt("COLUMNS");
            host_rows = microParsePositiveEnvInt("LINES");
            if (host_cols > 0 && host_rows > 0) {
                seed_source = "env";
            }
        }
        if (host_cols > 0 && host_rows > 0) {
            microApplyBridgeWinsizeLocked(bridge->session_id,
                                          bridge->pty_master,
                                          bridge->pty_slave,
                                          bridge->pty_use_shim,
                                          host_cols,
                                          host_rows);
            bridge->last_cols = host_cols;
            bridge->last_rows = host_rows;
            microResizeTracef("[micro-resize] micro bridgeSetup seeded-from-%s session=%llu cols=%d rows=%d",
                              seed_source,
                              (unsigned long long)bridge->session_id,
                              bridge->last_cols,
                              bridge->last_rows);
        }
    } else {
        microResizeTracef("[micro-resize] micro bridgeSetup seeded-from-session session=%llu cols=%d rows=%d",
                          (unsigned long long)bridge->session_id,
                          bridge->last_cols,
                          bridge->last_rows);
    }

    /* Feed micro stdin from the shell session stream. */
    bridge->stdin_ctx.read_fd = -1;
    bridge->stdin_ctx.write_fd = bridge->pipe_stdio_mode ? bridge->stdin_pipe_write : bridge->pty_master;
    bridge->stdin_ctx.read_host = false;
    bridge->stdin_ctx.read_vproc_shim = false;
    bridge->stdin_ctx.write_host = bridge->pipe_stdio_mode || !bridge->pty_use_shim;
    bridge->stdin_ctx.write_vproc_shim = (!bridge->pipe_stdio_mode && bridge->pty_use_shim);
    bridge->stdin_ctx.write_session_output = false;
    bridge->stdin_ctx.read_session_input = true;
    bridge->stdin_ctx.read_nonblocking = true;
    bridge->stdin_ctx.session_id = bridge->session_id;
    bridge->stdin_ctx.vp = bridge->pty_use_shim ? bridge->vp : NULL;
    bridge->stdin_ctx.session_stdio = bridge->session_stdio;
    bridge->stdin_ctx.stop_requested = &bridge->stop_requested;

    /* Output path A: interposed writes via PTY master (when PTY exists). */
    bridge->output_ctx.read_fd = bridge->pipe_stdio_mode ? -1 : bridge->pty_master;
    bridge->output_ctx.write_fd = -1;
    bridge->output_ctx.read_host = !bridge->pipe_stdio_mode && !bridge->pty_use_shim;
    bridge->output_ctx.read_vproc_shim = !bridge->pipe_stdio_mode && bridge->pty_use_shim;
    bridge->output_ctx.write_host = false;
    bridge->output_ctx.write_vproc_shim = false;
    bridge->output_ctx.write_session_output = true;
    bridge->output_ctx.read_session_input = false;
    bridge->output_ctx.read_nonblocking = false;
    bridge->output_ctx.session_id = bridge->session_id;
    bridge->output_ctx.vp = bridge->pty_use_shim ? bridge->vp : NULL;
    bridge->output_ctx.session_stdio = bridge->session_stdio;
    bridge->output_ctx.stop_requested = &bridge->stop_requested;

    /* Output path B: non-interposed writes captured from host stdout/stderr. */
    bridge->output_host_ctx.read_fd = bridge->pipe_stdio_mode ? bridge->output_pipe_read : -1;
    bridge->output_host_ctx.write_fd = -1;
    bridge->output_host_ctx.read_host = bridge->pipe_stdio_mode;
    bridge->output_host_ctx.read_vproc_shim = false;
    bridge->output_host_ctx.write_host = false;
    bridge->output_host_ctx.write_vproc_shim = false;
    bridge->output_host_ctx.write_session_output = true;
    bridge->output_host_ctx.read_session_input = false;
    bridge->output_host_ctx.read_nonblocking = false;
    bridge->output_host_ctx.session_id = bridge->session_id;
    bridge->output_host_ctx.vp = NULL;
    bridge->output_host_ctx.session_stdio = bridge->session_stdio;
    bridge->output_host_ctx.stop_requested = &bridge->stop_requested;

    if (vprocHostPthreadCreate(&bridge->stdin_thread, NULL, microIoBridgeThreadMain, &bridge->stdin_ctx) != 0) {
        goto fail;
    }
    bridge->stdin_thread_started = true;
    if (bridge->output_ctx.read_fd >= 0) {
        if (vprocHostPthreadCreate(&bridge->output_thread, NULL, microIoBridgeThreadMain, &bridge->output_ctx) != 0) {
            goto fail;
        }
        bridge->output_thread_started = true;
    }
    if (bridge->output_host_ctx.read_fd >= 0) {
        if (vprocHostPthreadCreate(&bridge->output_host_thread, NULL, microIoBridgeThreadMain, &bridge->output_host_ctx) != 0) {
            goto fail;
        }
        bridge->output_host_thread_started = true;
    }
    bridge->active = true;
    microBridgeStateSet(bridge->session_id,
                        bridge->pty_master,
                        bridge->pty_slave,
                        bridge->pty_use_shim);
    microResizeTracef("[micro-resize] micro bridgeSetup active session=%llu pty_master=%d pty_slave=%d shim=%d",
                      (unsigned long long)bridge->session_id,
                      bridge->pty_master,
                      bridge->pty_slave,
                      bridge->pty_use_shim ? 1 : 0);
    if (vprocHostPthreadCreate(&bridge->resize_thread, NULL, microBridgeResizeThreadMain, bridge) == 0) {
        bridge->resize_thread_started = true;
    } else if (microDebugEnabled()) {
        fprintf(stderr, "[micro-bridge] resize thread create failed errno=%d\n", errno);
    }
    if (microDebugEnabled()) {
        fprintf(stderr,
                "[micro-bridge] setup ok host_saved=(%d,%d,%d) session=%llu session_stdio=%p pty=(m:%d s:%d mode:%s)\n",
                bridge->saved_host_stdin,
                bridge->saved_host_stdout,
                bridge->saved_host_stderr,
                (unsigned long long)bridge->session_id,
                (void *)bridge->session_stdio,
                bridge->pty_master,
                bridge->pty_slave,
                bridge->pty_use_shim ? "shim" : (bridge->pipe_stdio_mode ? "pipe" : "host"));
    }
    return true;

fail:
    if (errno == 0) {
        errno = EIO;
    }
    microResizeTracef("[micro-resize] micro bridgeSetup failed errno=%d preferred=%llu",
                      errno,
                      (unsigned long long)preferred_session_id);
    fprintf(stderr,
            "micro: PTY bridge setup failed (session=%llu errno=%d: %s)\n",
            (unsigned long long)bridge->session_id,
            errno,
            strerror(errno));
    microHostStdioBridgeTeardown(bridge);
    return false;
}

static void microHostStdioBridgeTeardown(MicroHostStdioBridge *bridge) {
    if (!bridge) {
        return;
    }
    bridge->active = false;
    bridge->stop_requested = 1;
    microBridgeStateSet(bridge->session_id, -1, -1, false);

    if (bridge->stdio_redirected) {
        if (bridge->saved_host_stdin >= 0) {
            (void)vprocHostDup2(bridge->saved_host_stdin, STDIN_FILENO);
        }
        if (bridge->saved_host_stdout >= 0) {
            (void)vprocHostDup2(bridge->saved_host_stdout, STDOUT_FILENO);
        }
        if (bridge->saved_host_stderr >= 0) {
            (void)vprocHostDup2(bridge->saved_host_stderr, STDERR_FILENO);
        }
    }

    /* Closing the PTY fds wakes any blocking bridge reads. */
    microCloseIfOpen(&bridge->pty_slave, bridge->pty_use_shim);
    microCloseIfOpen(&bridge->pty_master, bridge->pty_use_shim);
    microCloseIfOpen(&bridge->stdin_pipe_read, false);
    microCloseIfOpen(&bridge->stdin_pipe_write, false);
    microCloseIfOpen(&bridge->output_pipe_read, false);
    microCloseIfOpen(&bridge->output_pipe_write, false);

    if (bridge->stdin_thread_started) {
        (void)pthread_join(bridge->stdin_thread, NULL);
        bridge->stdin_thread_started = false;
    }
    if (bridge->output_thread_started) {
        (void)pthread_join(bridge->output_thread, NULL);
        bridge->output_thread_started = false;
    }
    if (bridge->output_host_thread_started) {
        (void)pthread_join(bridge->output_host_thread, NULL);
        bridge->output_host_thread_started = false;
    }
    if (bridge->resize_thread_started) {
        (void)pthread_join(bridge->resize_thread, NULL);
        bridge->resize_thread_started = false;
    }

    microCloseIfOpen(&bridge->saved_host_stdin, false);
    microCloseIfOpen(&bridge->saved_host_stdout, false);
    microCloseIfOpen(&bridge->saved_host_stderr, false);
    bridge->active = false;
    bridge->session_stdio = NULL;
    bridge->vp = NULL;
    if (microDebugEnabled()) {
        fprintf(stderr, "[micro-bridge] teardown complete\n");
    }
}
#endif

#if !defined(PSCAL_TARGET_IOS)
static int microSetupTty(void) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd >= 0) {
        if (fd != STDIN_FILENO) {
            dup2(fd, STDIN_FILENO);
        }
        if (fd != STDOUT_FILENO) {
            dup2(fd, STDOUT_FILENO);
        }
        if (fd != STDERR_FILENO) {
            dup2(fd, STDERR_FILENO);
        }
    }
    return fd;
}
#endif

#if !defined(PSCAL_TARGET_IOS)
typedef struct {
    unsigned char bytes[4];
    size_t have;
    size_t expect;
} MicroUtf8State;

static bool microOptionAltEnabled(void) {
    const char *env = getenv("PSCALI_MICRO_OPTION_IS_ALT");
    if (!env || !*env) {
        return true;
    }
    return strcmp(env, "0") != 0;
}

static bool microMapOptionRuneToAlt(uint32_t cp, unsigned char *out_key) {
    if (!out_key) {
        return false;
    }
    switch (cp) {
        case 0x00E5: *out_key = 'a'; return true; /* Option+a */
        case 0x222B: *out_key = 'b'; return true; /* Option+b */
        case 0x00E7: *out_key = 'c'; return true; /* Option+c */
        case 0x2202: *out_key = 'd'; return true; /* Option+d */
        case 0x00B4: *out_key = 'e'; return true; /* Option+e */
        case 0x0192: *out_key = 'f'; return true; /* Option+f */
        case 0x00A9: *out_key = 'g'; return true; /* Option+g */
        case 0x02D9: *out_key = 'h'; return true; /* Option+h */
        case 0x02C6: *out_key = 'i'; return true; /* Option+i */
        case 0x2206: *out_key = 'j'; return true; /* Option+j */
        case 0x02DA: *out_key = 'k'; return true; /* Option+k */
        case 0x00AC: *out_key = 'l'; return true; /* Option+l */
        case 0x00B5: *out_key = 'm'; return true; /* Option+m */
        case 0x02DC: *out_key = 'n'; return true; /* Option+n */
        case 0x00F8: *out_key = 'o'; return true; /* Option+o */
        case 0x03C0: *out_key = 'p'; return true; /* Option+p */
        case 0x0153: *out_key = 'q'; return true; /* Option+q */
        case 0x00AE: *out_key = 'r'; return true; /* Option+r */
        case 0x00DF: *out_key = 's'; return true; /* Option+s */
        case 0x2020: *out_key = 't'; return true; /* Option+t */
        case 0x00A8: *out_key = 'u'; return true; /* Option+u */
        case 0x221A: *out_key = 'v'; return true; /* Option+v */
        case 0x2211: *out_key = 'w'; return true; /* Option+w */
        case 0x2248: *out_key = 'x'; return true; /* Option+x */
        case 0x00A5: *out_key = 'y'; return true; /* Option+y */
        case 0x03A9: *out_key = 'z'; return true; /* Option+z */
        case 0x2265: *out_key = '.'; return true; /* Option+. */
        default:
            break;
    }
    return false;
}

static bool microDecodeUtf8(const unsigned char *bytes, size_t len, uint32_t *out_cp) {
    if (!bytes || !out_cp) {
        return false;
    }
    if (len == 1 && (bytes[0] & 0x80) == 0) {
        *out_cp = bytes[0];
        return true;
    }
    if (len == 2 && (bytes[0] & 0xE0) == 0xC0 &&
        (bytes[1] & 0xC0) == 0x80) {
        *out_cp = ((uint32_t)(bytes[0] & 0x1F) << 6) |
                  (uint32_t)(bytes[1] & 0x3F);
        return true;
    }
    if (len == 3 && (bytes[0] & 0xF0) == 0xE0 &&
        (bytes[1] & 0xC0) == 0x80 &&
        (bytes[2] & 0xC0) == 0x80) {
        *out_cp = ((uint32_t)(bytes[0] & 0x0F) << 12) |
                  ((uint32_t)(bytes[1] & 0x3F) << 6) |
                  (uint32_t)(bytes[2] & 0x3F);
        return true;
    }
    if (len == 4 && (bytes[0] & 0xF8) == 0xF0 &&
        (bytes[1] & 0xC0) == 0x80 &&
        (bytes[2] & 0xC0) == 0x80 &&
        (bytes[3] & 0xC0) == 0x80) {
        *out_cp = ((uint32_t)(bytes[0] & 0x07) << 18) |
                  ((uint32_t)(bytes[1] & 0x3F) << 12) |
                  ((uint32_t)(bytes[2] & 0x3F) << 6) |
                  (uint32_t)(bytes[3] & 0x3F);
        return true;
    }
    return false;
}

static int microWriteAll(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void microUtf8StateReset(MicroUtf8State *st) {
    if (!st) {
        return;
    }
    st->have = 0;
    st->expect = 0;
}

static bool microTranslateOptionByte(MicroUtf8State *st,
                                     unsigned char in,
                                     unsigned char *out,
                                     size_t *out_len) {
    if (!st || !out || !out_len) {
        return false;
    }
    *out_len = 0;

    if (st->expect == 0) {
        if ((in & 0x80) == 0) {
            out[0] = in;
            *out_len = 1;
            return true;
        }
        if ((in & 0xE0) == 0xC0) {
            st->expect = 2;
        } else if ((in & 0xF0) == 0xE0) {
            st->expect = 3;
        } else if ((in & 0xF8) == 0xF0) {
            st->expect = 4;
        } else {
            out[0] = in;
            *out_len = 1;
            return true;
        }
        st->bytes[0] = in;
        st->have = 1;
        return false;
    }

    if ((in & 0xC0) != 0x80) {
        size_t flush = st->have;
        memcpy(out, st->bytes, flush);
        out[flush] = in;
        *out_len = flush + 1;
        microUtf8StateReset(st);
        return true;
    }

    st->bytes[st->have++] = in;
    if (st->have < st->expect) {
        return false;
    }

    uint32_t cp = 0;
    unsigned char alt_key = 0;
    if (microDecodeUtf8(st->bytes, st->expect, &cp) &&
        microMapOptionRuneToAlt(cp, &alt_key)) {
        out[0] = 0x1B;
        out[1] = alt_key;
        *out_len = 2;
    } else {
        memcpy(out, st->bytes, st->expect);
        *out_len = st->expect;
    }
    microUtf8StateReset(st);
    return true;
}

static void microApplyWinsizeFromStdin(int pty_master) {
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 &&
        ws.ws_col > 0 && ws.ws_row > 0) {
        (void)ioctl(pty_master, TIOCSWINSZ, &ws);
    }
}

static int microRunExternalWithOptionAlt(const char *candidate,
                                         int execArgc,
                                         char **execArgv) {
    int pty_master = posix_openpt(O_RDWR | O_NOCTTY);
    if (pty_master < 0) {
        return -1;
    }
    if (grantpt(pty_master) != 0 || unlockpt(pty_master) != 0) {
        close(pty_master);
        return -1;
    }

    char pty_slave_name[128];
    memset(pty_slave_name, 0, sizeof(pty_slave_name));
#if defined(__linux__)
    if (ptsname_r(pty_master, pty_slave_name, sizeof(pty_slave_name)) != 0) {
        close(pty_master);
        return -1;
    }
#else
    char *pts_name = ptsname(pty_master);
    if (!pts_name || !*pts_name) {
        close(pty_master);
        return -1;
    }
    snprintf(pty_slave_name, sizeof(pty_slave_name), "%s", pts_name);
#endif

    pid_t child = fork();
    if (child < 0) {
        close(pty_master);
        return -1;
    }
    if (child == 0) {
        int pty_slave = -1;
        setsid();
        pty_slave = open(pty_slave_name, O_RDWR | O_NOCTTY);
        if (pty_slave < 0) {
            _exit(127);
        }
        (void)ioctl(pty_slave, TIOCSCTTY, 0);
        if (pty_slave != STDIN_FILENO) {
            dup2(pty_slave, STDIN_FILENO);
        }
        if (pty_slave != STDOUT_FILENO) {
            dup2(pty_slave, STDOUT_FILENO);
        }
        if (pty_slave != STDERR_FILENO) {
            dup2(pty_slave, STDERR_FILENO);
        }
        if (pty_slave > STDERR_FILENO) {
            close(pty_slave);
        }
        close(pty_master);
        execv(candidate, execArgv);
        _exit(127);
    }

    microApplyWinsizeFromStdin(pty_master);

    bool stdin_is_tty = isatty(STDIN_FILENO);
    struct termios saved_termios;
    bool saved_termios_valid = false;
    if (stdin_is_tty && tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
        struct termios raw = saved_termios;
        cfmakeraw(&raw);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
            saved_termios_valid = true;
        }
    }

    bool stdin_open = true;
    int child_status = 0;
    bool child_exited = false;
    MicroUtf8State utf8_state;
    microUtf8StateReset(&utf8_state);

    while (true) {
        if (!child_exited) {
            pid_t w = waitpid(child, &child_status, WNOHANG);
            if (w == child) {
                child_exited = true;
            }
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        int maxfd = pty_master;
        FD_SET(pty_master, &readfds);
        if (stdin_open) {
            FD_SET(STDIN_FILENO, &readfds);
            if (STDIN_FILENO > maxfd) {
                maxfd = STDIN_FILENO;
            }
        }

        int sel = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (sel < 0) {
            if (errno == EINTR) {
                if (stdin_is_tty) {
                    microApplyWinsizeFromStdin(pty_master);
                }
                continue;
            }
            break;
        }

        if (stdin_open && FD_ISSET(STDIN_FILENO, &readfds)) {
            unsigned char in = 0;
            ssize_t nr = read(STDIN_FILENO, &in, 1);
            if (nr <= 0) {
                stdin_open = false;
            } else {
                unsigned char out[8];
                size_t out_len = 0;
                if (microTranslateOptionByte(&utf8_state, in, out, &out_len) && out_len > 0) {
                    if (microWriteAll(pty_master, out, out_len) != 0) {
                        break;
                    }
                }
            }
        }

        if (FD_ISSET(pty_master, &readfds)) {
            unsigned char outbuf[4096];
            ssize_t nr = read(pty_master, outbuf, sizeof(outbuf));
            if (nr <= 0) {
                break;
            }
            if (microWriteAll(STDOUT_FILENO, outbuf, (size_t)nr) != 0) {
                break;
            }
        }
    }

    if (utf8_state.have > 0) {
        (void)microWriteAll(pty_master, utf8_state.bytes, utf8_state.have);
    }

    if (!child_exited) {
        (void)waitpid(child, &child_status, 0);
    }
    close(pty_master);

    if (saved_termios_valid) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    }

    if (WIFEXITED(child_status)) {
        return WEXITSTATUS(child_status);
    }
    if (WIFSIGNALED(child_status)) {
        return 128 + WTERMSIG(child_status);
    }
    return 1;
}

static int microExecExternalBinary(int argc, char **argv) {
    const char *overridePath = getenv("PSCAL_MICRO_EXTERNAL");
    const char *candidates[4];
    size_t count = 0;
    if (overridePath && *overridePath) {
        candidates[count++] = overridePath;
    }
    candidates[count++] = "/usr/bin/micro-real";
    candidates[count++] = "/usr/local/bin/micro-real";
    candidates[count] = NULL;

    for (size_t i = 0; i < count; ++i) {
        const char *candidate = candidates[i];
        if (!candidate || access(candidate, X_OK) != 0) {
            continue;
        }

        int execArgc = argc > 0 ? argc : 1;
        char **execArgv = (char **)calloc((size_t)execArgc + 1, sizeof(char *));
        if (!execArgv) {
            fprintf(stderr, "micro: out of memory preparing external launch\n");
            return 1;
        }
        execArgv[0] = (char *)candidate;
        for (int argIndex = 1; argIndex < execArgc; ++argIndex) {
            execArgv[argIndex] = argv[argIndex];
        }
        execArgv[execArgc] = NULL;
        if (microOptionAltEnabled() && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
            int relayStatus = microRunExternalWithOptionAlt(candidate, execArgc, execArgv);
            if (relayStatus >= 0) {
                free(execArgv);
                return relayStatus;
            }
            if (microDebugEnabled()) {
                fprintf(stderr, "micro: option-alt relay unavailable; falling back to direct exec\n");
            }
        }
        execv(candidate, execArgv);
        free(execArgv);
        fprintf(stderr, "micro: failed to exec %s: %s\n", candidate, strerror(errno));
        return 127;
    }

    fprintf(stderr,
            "micro: embedded runtime unavailable and no external micro binary found (expected /usr/bin/micro-real)\n");
    return 127;
}
#endif

int smallclueRunMicro(int argc, char **argv) {
#if defined(PSCAL_TARGET_IOS)
    uint64_t launchSessionId = 0;
    VProcSessionStdio *launchSession = vprocSessionStdioCurrent();
    VProcSessionStdio *runtimeSession = NULL;
    uint64_t runtimeSessionId = 0;
    if (PSCALRuntimeGetCurrentRuntimeStdio) {
        runtimeSession = PSCALRuntimeGetCurrentRuntimeStdio();
        if (runtimeSession && runtimeSession->session_id != 0) {
            runtimeSessionId = runtimeSession->session_id;
        }
    }
    if (PSCALRuntimeCurrentSessionId) {
        uint64_t currentRuntimeSessionId = PSCALRuntimeCurrentSessionId();
        if (currentRuntimeSessionId != 0) {
            runtimeSessionId = currentRuntimeSessionId;
        }
    }
    if ((!launchSession || launchSession->session_id == 0) &&
        runtimeSession && runtimeSession->session_id != 0) {
        launchSession = runtimeSession;
    }
    if (launchSession) {
        launchSessionId = launchSession->session_id;
    }
    if (launchSessionId == 0 && runtimeSessionId != 0) {
        launchSessionId = runtimeSessionId;
    } else if (launchSessionId != 0 &&
               runtimeSessionId != 0 &&
               launchSessionId != runtimeSessionId) {
        microResizeTracef("[micro-resize] micro launch session mismatch launch=%llu runtime=%llu",
                          (unsigned long long)launchSessionId,
                          (unsigned long long)runtimeSessionId);
    }
    if (launchSessionId == 0) {
        microResizeTracef("[micro-resize] micro launch missing thread-local session");
    }
    {
        int launchCols = 0;
        int launchRows = 0;
        const char *launchSource = "none";
        if (microResolveLaunchWinsize(launchSessionId,
                                      launchSession,
                                      &launchCols,
                                      &launchRows,
                                      &launchSource)) {
            microUpdateSizeEnv(launchCols, launchRows);
            microResizeTracef("[micro-resize] micro launch seeded env source=%s session=%llu cols=%d rows=%d",
                              launchSource,
                              (unsigned long long)launchSessionId,
                              launchCols,
                              launchRows);
        } else {
            microResizeTracef("[micro-resize] micro launch unable to resolve winsize session=%llu",
                              (unsigned long long)launchSessionId);
        }
    }
    uint64_t mainThreadSessionId = launchSessionId;
    microBridgeMainThreadSet(mainThreadSessionId, pthread_self(), true);
#endif
    MicroEnvBackup envBackup;
    microPrepareEnvironment(&envBackup);
#if defined(PSCAL_TARGET_IOS)
#endif
    const char *microConfigHome = getenv("MICRO_CONFIG_HOME");
    int launchArgc = argc;
    char **launchArgv = argv;
    char **patchedArgv = microInjectConfigDirArgv(argc, argv, microConfigHome, &launchArgc);
    if (patchedArgv) {
        launchArgv = patchedArgv;
    }
#if !defined(PSCAL_TARGET_IOS)
    extern int pscal_micro_main_entry(int argc, char **argv) __attribute__((weak));
    if (!pscal_micro_main_entry) {
        int externalStatus = microExecExternalBinary(launchArgc, launchArgv);
        free(patchedArgv);
        microRestoreEnvironment(&envBackup);
        return externalStatus;
    }
#endif
#if defined(PSCAL_TARGET_IOS)
    MicroHostStdioBridge hostBridge;
    bool hostBridgeActive = false;
    int launchTcellStdinFd = STDIN_FILENO;
    int launchTcellStdoutFd = STDOUT_FILENO;
    const bool bridgeRequested = true;
    const bool bridgeStrictFailure = true;
    if (bridgeRequested) {
        hostBridgeActive = microHostStdioBridgeSetup(&hostBridge,
                                                     launchSession,
                                                     launchSessionId);
        if (!hostBridgeActive) {
            int bridge_errno = errno;
            if (bridgeStrictFailure) {
                fprintf(stderr,
                        "micro: unable to initialize PTY bridge (strict mode, errno=%d)\n",
                        bridge_errno);
                free(patchedArgv);
                microRestoreEnvironment(&envBackup);
                microBridgeMainThreadSet(mainThreadSessionId, (pthread_t)0, false);
                return 1;
            }
            fprintf(stderr,
                    "micro: unable to initialize PTY bridge (errno=%d), continuing without bridge\n",
                    bridge_errno);
        }
    }
    microResizeTracef("[micro-resize] micro bridge requested=%d active=%d launch_session=%llu bridge_session=%llu",
                      bridgeRequested ? 1 : 0,
                      hostBridgeActive ? 1 : 0,
                      (unsigned long long)launchSessionId,
                      (unsigned long long)hostBridge.session_id);
    if (hostBridgeActive &&
        hostBridge.session_id != 0 &&
        hostBridge.session_id != mainThreadSessionId) {
        microBridgeMainThreadSet(mainThreadSessionId, (pthread_t)0, false);
        mainThreadSessionId = hostBridge.session_id;
        microBridgeMainThreadSet(mainThreadSessionId, pthread_self(), true);
    }
    if (microDebugEnabled()) {
        fprintf(stderr,
                "[micro] host stdio bridge requested=%d active=%d\n",
                bridgeRequested ? 1 : 0,
                hostBridgeActive ? 1 : 0);
    }
    if (hostBridgeActive) {
        if (hostBridge.pipe_stdio_mode) {
            launchTcellStdinFd = hostBridge.stdin_pipe_read;
            launchTcellStdoutFd = hostBridge.output_pipe_write;
        } else if (hostBridge.pty_slave >= 0) {
            launchTcellStdinFd = hostBridge.pty_slave;
            launchTcellStdoutFd = hostBridge.pty_slave;
        }
    }
    {
        uint64_t goLaunchSessionId = hostBridge.session_id != 0
                                     ? hostBridge.session_id
                                     : launchSessionId;
        microGoLaunchContextSet(goLaunchSessionId,
                                launchTcellStdinFd,
                                launchTcellStdoutFd);
    }
#endif
    MicroStdFdBackup stdioBackup;
#if !defined(PSCAL_TARGET_IOS)
    microSaveStandardFds(&stdioBackup);
#else
    memset(&stdioBackup, 0, sizeof(stdioBackup));
#endif
    int dupFd = -1;
#if defined(PSCAL_TARGET_IOS)
    if (hostBridgeActive && microDebugEnabled()) {
        fprintf(stderr, "[micro] skipping microSetupTty while host bridge is active\n");
    }
#else
    dupFd = microSetupTty();
#endif
    struct termios savedIos;
    bool savedIosValid = false;
    bool appliedRawMode = false;
    int ttyFd = STDIN_FILENO;
    bool haveTty = false;
    if (smallclueTcgetattr(ttyFd, &savedIos) != 0) {
#if defined(PSCAL_TARGET_IOS)
        /* On iOS keep micro bound to the active session stdio; do not fall back
         * to opening /dev/tty (that can route to Xcode console instead of vpty). */
        haveTty = false;
        savedIosValid = false;
#else
        ttyFd = dupFd >= 0 ? dupFd : open("/dev/tty", O_RDWR);
        if (ttyFd >= 0 && smallclueTcgetattr(ttyFd, &savedIos) == 0) {
            haveTty = true;
            savedIosValid = true;
        }
#endif
    } else {
        haveTty = true;
        savedIosValid = true;
    }
#if defined(PSCAL_TARGET_IOS)
    bool shouldApplyRawMode = !hostBridgeActive;
#else
    bool shouldApplyRawMode = true;
#endif
    if (haveTty && shouldApplyRawMode) {
        struct termios raw = savedIos;
        raw.c_lflag &= ~(ICANON | ECHO | IEXTEN | ISIG);
        raw.c_iflag &= ~(ICRNL | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        smallclueTcsetattr(ttyFd, TCSAFLUSH, &raw);
        tcflush(ttyFd, TCIFLUSH);
        appliedRawMode = true;
    }

    int status = 1;
#if defined(PSCAL_TARGET_IOS)
    vprocProtectKqueueCloseEnter();
    extern int pscal_micro_main_entry(int argc, char **argv);
    status = pscal_micro_main_entry(launchArgc, launchArgv);
    vprocProtectKqueueCloseExit();
#else
    status = pscal_micro_main_entry(launchArgc, launchArgv);
#endif

    if (haveTty && savedIosValid && appliedRawMode) {
        smallclueTcsetattr(ttyFd, TCSAFLUSH, &savedIos);
        if (ttyFd != STDIN_FILENO) {
            smallclueTcsetattr(STDIN_FILENO, TCSAFLUSH, &savedIos);
        }
        tcflush(STDIN_FILENO, TCIOFLUSH);
        tcflush(ttyFd, TCIOFLUSH);
        if (ttyFd != STDIN_FILENO) {
            close(ttyFd);
        }
    }
    if (isatty(STDOUT_FILENO)
#if defined(PSCAL_TARGET_IOS)
        && !hostBridgeActive
#endif
    ) {
        static const char resetSeq[] = "\033[r\033[?1l\033>\033[?25h\033[?1049l\033[?47l";
        static const char clearSeq[] = "\033[2J\033[H\r\n";
        (void)write(STDOUT_FILENO, resetSeq, sizeof(resetSeq) - 1);
        (void)write(STDOUT_FILENO, clearSeq, sizeof(clearSeq) - 1);
        (void)tcdrain(STDOUT_FILENO);
    }
    if (dupFd >= 0 && dupFd != STDIN_FILENO && dupFd != ttyFd) {
        close(dupFd);
    }

#if !defined(PSCAL_TARGET_IOS)
    microRestoreStandardFds(&stdioBackup);
#endif
#if defined(PSCAL_TARGET_IOS)
    microGoLaunchContextClear();
    if (hostBridgeActive) {
        microHostStdioBridgeTeardown(&hostBridge);
    }
    microBridgeMainThreadSet(mainThreadSessionId, (pthread_t)0, false);
#endif
    free(patchedArgv);
    microRestoreEnvironment(&envBackup);
#if defined(PSCAL_TARGET_IOS)
#endif
    return status;
}

#if defined(PSCAL_TARGET_IOS)
extern int pscal_micro_go_main_entry(int argc, char **argv);

int pscal_micro_main_entry(int argc, char **argv) {
    return pscal_micro_go_main_entry(argc, argv);
}
#endif
