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
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

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
static pthread_mutex_t gMicroLaunchMu = PTHREAD_MUTEX_INITIALIZER;
static bool gMicroLaunchActive = false;
static uint64_t gMicroLaunchSessionId = 0;
static pthread_mutex_t gMicroBridgeStateMu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t gMicroBridgeSessionId = 0;
static int gMicroBridgePtyMaster = -1;
static int gMicroBridgePtySlave = -1;
static bool gMicroBridgePtyUseShim = false;
static pthread_t gMicroMainThread;
static bool gMicroMainThreadValid = false;

static void microBridgeStateSet(uint64_t session_id,
                                int pty_master,
                                int pty_slave,
                                bool pty_use_shim) {
    pthread_mutex_lock(&gMicroBridgeStateMu);
    gMicroBridgeSessionId = session_id;
    gMicroBridgePtyMaster = pty_master;
    gMicroBridgePtySlave = pty_slave;
    gMicroBridgePtyUseShim = pty_use_shim;
    microResizeTracef("[micro-resize] micro bridgeStateSet session=%llu pty_master=%d pty_slave=%d shim=%d",
                      (unsigned long long)session_id,
                      pty_master,
                      pty_slave,
                      pty_use_shim ? 1 : 0);
    pthread_mutex_unlock(&gMicroBridgeStateMu);
}

static void microBridgeMainThreadSet(pthread_t tid, bool valid) {
    pthread_mutex_lock(&gMicroBridgeStateMu);
    gMicroMainThread = tid;
    gMicroMainThreadValid = valid;
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

static void microApplyBridgeWinsizeLocked(int pty_master,
                                          int pty_slave,
                                          bool use_shim_ioctl,
                                          int cols,
                                          int rows) {
    if ((pty_master < 0 && pty_slave < 0) || cols <= 0 || rows <= 0) {
        return;
    }
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)cols;
    ws.ws_row = (unsigned short)rows;
    if (use_shim_ioctl) {
        if (!vprocCurrent()) {
            return;
        }
        if (pty_slave >= 0) {
            (void)vprocIoctlShim(pty_slave, TIOCSWINSZ, &ws);
        }
        if (pty_master >= 0) {
            (void)vprocIoctlShim(pty_master, TIOCSWINSZ, &ws);
        }
    } else {
        if (pty_slave >= 0) {
            (void)ioctl(pty_slave, TIOCSWINSZ, &ws);
        }
        if (pty_master >= 0) {
            (void)ioctl(pty_master, TIOCSWINSZ, &ws);
        }
    }
    microUpdateSizeEnv(cols, rows);
    microResizeTracef("[micro-resize] micro applyBridgeWinsize pty_master=%d pty_slave=%d cols=%d rows=%d shim=%d",
                      pty_master,
                      pty_slave,
                      cols,
                      rows,
                      use_shim_ioctl ? 1 : 0);
}

static void microSignalResizeLocked(void) {
#ifdef SIGWINCH
    if (gMicroMainThreadValid) {
        int rc = pthread_kill(gMicroMainThread, SIGWINCH);
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
    bool match = (gMicroBridgeSessionId == session_id);
    int pty_master = match ? gMicroBridgePtyMaster : -1;
    int pty_slave = match ? gMicroBridgePtySlave : -1;
    bool pty_use_shim = match ? gMicroBridgePtyUseShim : false;
    if (match || miss_log_budget > 0) {
        microResizeTracef("[micro-resize] micro notifySessionWinsize session=%llu cols=%d rows=%d match=%d state_session=%llu pty_master=%d pty_slave=%d shim=%d",
                          (unsigned long long)session_id,
                          cols,
                          rows,
                          match ? 1 : 0,
                          (unsigned long long)gMicroBridgeSessionId,
                          pty_master,
                          pty_slave,
                          pty_use_shim ? 1 : 0);
        if (!match && miss_log_budget > 0) {
            miss_log_budget--;
        }
    }
    microApplyBridgeWinsizeLocked(pty_master, pty_slave, pty_use_shim, cols, rows);
    if (pty_master >= 0 || pty_slave >= 0) {
        microSignalResizeLocked();
    }
    pthread_mutex_unlock(&gMicroBridgeStateMu);
}

static bool microAcquireLaunchSlot(uint64_t session_id, uint64_t *active_session_id) {
    bool acquired = false;
    pthread_mutex_lock(&gMicroLaunchMu);
    if (!gMicroLaunchActive) {
        gMicroLaunchActive = true;
        gMicroLaunchSessionId = session_id;
        acquired = true;
    } else if (active_session_id) {
        *active_session_id = gMicroLaunchSessionId;
    }
    pthread_mutex_unlock(&gMicroLaunchMu);
    return acquired;
}

static void microReleaseLaunchSlot(void) {
    pthread_mutex_lock(&gMicroLaunchMu);
    gMicroLaunchActive = false;
    gMicroLaunchSessionId = 0;
    pthread_mutex_unlock(&gMicroLaunchMu);
}

static void microReportLaunchBusy(uint64_t requester_session_id,
                                  uint64_t active_session_id) {
    char msg[192];
    int n = 0;
    if (active_session_id != 0) {
        n = snprintf(msg,
                     sizeof(msg),
                     "micro: another instance is already running (session %llu)\r\n",
                     (unsigned long long)active_session_id);
    } else {
        n = snprintf(msg, sizeof(msg),
                     "micro: another instance is already running\r\n");
    }
    if (n <= 0) {
        return;
    }
    size_t len = (size_t)n;
    if (requester_session_id != 0) {
        if (vprocSessionEmitOutput(requester_session_id, msg, len) >= 0) {
            return;
        }
    }
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
    microApplyBridgeWinsizeLocked(bridge->pty_master,
                                  bridge->pty_slave,
                                  bridge->pty_use_shim,
                                  cols,
                                  rows);
    if (signal_resize) {
        microSignalResizeLocked();
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
        int host_ptmx_errno = errno;
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
            const char *allow_shim_env = getenv("PSCALI_MICRO_ALLOW_SHIM_PTY");
            /* iOS should use vproc virtual PTYs by default. Allow disabling
             * only for targeted diagnostics with PSCALI_MICRO_ALLOW_SHIM_PTY=0. */
            bool allow_shim_fallback = true;
            if (allow_shim_env && strcmp(allow_shim_env, "0") == 0) {
                allow_shim_fallback = false;
            }
            int pty_num = -1;
            int unlocked = 0;
            char pty_slave_name[64];
            if (allow_shim_fallback) {
                bridge->pty_master = vprocOpenShim("/dev/ptmx", O_RDWR | O_NOCTTY, 0);
                if (bridge->pty_master >= 0) {
                    bridge->pty_use_shim = true;
                    bridge->vp = vprocCurrent();
                    (void)vprocIoctlShim(bridge->pty_master, TIOCSPTLCK_, &unlocked);
                    if (vprocIoctlShim(bridge->pty_master, TIOCGPTN_, &pty_num) == 0 && pty_num >= 0) {
                        snprintf(pty_slave_name, sizeof(pty_slave_name), "/dev/pts/%d", pty_num);
                        bridge->pty_slave = vprocOpenShim(pty_slave_name, O_RDWR | O_NOCTTY, 0);
                        if (bridge->pty_slave < 0) {
                            microCloseIfOpen(&bridge->pty_master, true);
                            bridge->pty_use_shim = false;
                            bridge->vp = NULL;
                        }
                    } else {
                        microCloseIfOpen(&bridge->pty_master, true);
                        bridge->pty_use_shim = false;
                        bridge->vp = NULL;
                    }
                } else if (microDebugEnabled()) {
                    fprintf(stderr,
                            "[micro-bridge] bridgeSetup shim PTY unavailable: host errno=%d shim errno=%d\n",
                            host_ptmx_errno,
                            errno);
                }
            } else if (microDebugEnabled()) {
                fprintf(stderr,
                        "[micro-bridge] bridgeSetup host PTY unavailable errno=%d (shim fallback disabled)\n",
                        host_ptmx_errno);
            }
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
    } else if (bridge->pty_slave >= 0) {
        if (vprocHostDup2(bridge->pty_slave, STDIN_FILENO) < 0 ||
            vprocHostDup2(bridge->pty_slave, STDOUT_FILENO) < 0 ||
            vprocHostDup2(bridge->pty_slave, STDERR_FILENO) < 0) {
            goto fail;
        }
    }

    if (bridge->pipe_stdio_mode) {
        if (vprocHostDup2(bridge->stdin_pipe_read, STDIN_FILENO) < 0 ||
            vprocHostDup2(bridge->output_pipe_write, STDOUT_FILENO) < 0 ||
            vprocHostDup2(bridge->output_pipe_write, STDERR_FILENO) < 0) {
            goto fail;
        }
    }
    /* Seed initial size from the active session PTY when available. This is
     * more reliable than host stdout in embedded/iOS contexts. */
    if (!microBridgeApplySessionWinsize(bridge, true, false)) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        if (bridge->saved_host_stdout >= 0 &&
            ioctl(bridge->saved_host_stdout, TIOCGWINSZ, &ws) == 0 &&
            ws.ws_col > 0 &&
            ws.ws_row > 0) {
            microApplyBridgeWinsizeLocked(bridge->pty_master,
                                          bridge->pty_slave,
                                          bridge->pty_use_shim,
                                          (int)ws.ws_col,
                                          (int)ws.ws_row);
            bridge->last_cols = (int)ws.ws_col;
            bridge->last_rows = (int)ws.ws_row;
            microResizeTracef("[micro-resize] micro bridgeSetup seeded-from-host session=%llu cols=%d rows=%d",
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
    if (!bridge->pipe_stdio_mode) {
        if (vprocHostPthreadCreate(&bridge->resize_thread, NULL, microBridgeResizeThreadMain, bridge) == 0) {
            bridge->resize_thread_started = true;
        } else if (microDebugEnabled()) {
            fprintf(stderr, "[micro-bridge] resize thread create failed errno=%d\n", errno);
        }
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
    microBridgeStateSet(0, -1, -1, false);

    if (bridge->saved_host_stdin >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stdin, STDIN_FILENO);
    }
    if (bridge->saved_host_stdout >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stdout, STDOUT_FILENO);
    }
    if (bridge->saved_host_stderr >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stderr, STDERR_FILENO);
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

int smallclueRunMicro(int argc, char **argv) {
#if defined(PSCAL_TARGET_IOS)
    uint64_t launchSessionId = 0;
    uint64_t activeSessionId = 0;
    bool launchSlotAcquired = false;
    VProcSessionStdio *launchSession = vprocSessionStdioCurrent();
    if ((!launchSession || launchSession->session_id == 0) &&
        PSCALRuntimeGetCurrentRuntimeStdio) {
        VProcSessionStdio *runtimeSession = PSCALRuntimeGetCurrentRuntimeStdio();
        if (runtimeSession && runtimeSession->session_id != 0) {
            launchSession = runtimeSession;
        }
    }
    if (launchSession) {
        launchSessionId = launchSession->session_id;
    }
    if (launchSessionId == 0 && PSCALRuntimeCurrentSessionId) {
        launchSessionId = PSCALRuntimeCurrentSessionId();
    }
    if (launchSessionId != 0) {
        int launchCols = 0;
        int launchRows = 0;
        if (vprocGetSessionWinsize(launchSessionId, &launchCols, &launchRows) == 0 &&
            launchCols > 0 &&
            launchRows > 0) {
            microUpdateSizeEnv(launchCols, launchRows);
            microResizeTracef("[micro-resize] micro launch seeded env session=%llu cols=%d rows=%d",
                              (unsigned long long)launchSessionId,
                              launchCols,
                              launchRows);
        } else {
            microResizeTracef("[micro-resize] micro launch no-session-size session=%llu",
                              (unsigned long long)launchSessionId);
        }
    } else {
        microResizeTracef("[micro-resize] micro launch has no session id");
    }
    if (!microAcquireLaunchSlot(launchSessionId, &activeSessionId)) {
        microReportLaunchBusy(launchSessionId, activeSessionId);
        return 1;
    }
    launchSlotAcquired = true;
    microBridgeMainThreadSet(pthread_self(), true);
#endif
    MicroEnvBackup envBackup;
    microPrepareEnvironment(&envBackup);
    const char *microConfigHome = getenv("MICRO_CONFIG_HOME");
    int launchArgc = argc;
    char **launchArgv = argv;
    char **patchedArgv = microInjectConfigDirArgv(argc, argv, microConfigHome, &launchArgc);
    if (patchedArgv) {
        launchArgv = patchedArgv;
    }
#if defined(PSCAL_TARGET_IOS)
    MicroHostStdioBridge hostBridge;
    bool hostBridgeActive = false;
    bool bridgeStrictFailure = true;
    const char *enableBridge = getenv("PSCALI_MICRO_HOST_BRIDGE");
    bool bridgeRequested = true;
    if (enableBridge && strcmp(enableBridge, "0") == 0) {
        bridgeRequested = false;
    }
    const char *bridgeStrict = getenv("PSCALI_MICRO_BRIDGE_STRICT");
    if (bridgeStrict && strcmp(bridgeStrict, "0") == 0) {
        bridgeStrictFailure = false;
    }
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
                microBridgeMainThreadSet((pthread_t)0, false);
                if (launchSlotAcquired) {
                    microReleaseLaunchSlot();
                }
                return 1;
            }
            fprintf(stderr,
                    "micro: unable to initialize PTY bridge (errno=%d), continuing without bridge\n",
                    bridge_errno);
        }
        if (hostBridgeActive && hostBridge.pipe_stdio_mode && bridgeStrictFailure) {
            fprintf(stderr,
                    "micro: unable to initialize PTY bridge (strict mode, no PTY available)\n");
            microHostStdioBridgeTeardown(&hostBridge);
            hostBridgeActive = false;
            free(patchedArgv);
            microRestoreEnvironment(&envBackup);
            microBridgeMainThreadSet((pthread_t)0, false);
            if (launchSlotAcquired) {
                microReleaseLaunchSlot();
            }
            return 1;
        }
    }
    microResizeTracef("[micro-resize] micro bridge requested=%d active=%d launch_session=%llu bridge_session=%llu",
                      bridgeRequested ? 1 : 0,
                      hostBridgeActive ? 1 : 0,
                      (unsigned long long)launchSessionId,
                      (unsigned long long)hostBridge.session_id);
    if (microDebugEnabled()) {
        fprintf(stderr,
                "[micro] host stdio bridge requested=%d active=%d\n",
                bridgeRequested ? 1 : 0,
                hostBridgeActive ? 1 : 0);
    }
#endif
    MicroStdFdBackup stdioBackup;
    microSaveStandardFds(&stdioBackup);
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
    extern int pscal_micro_main_entry(int argc, char **argv) __attribute__((weak));
    if (!pscal_micro_main_entry) {
        status = 127;
    } else {
        status = pscal_micro_main_entry(launchArgc, launchArgv);
    }
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
    if (isatty(STDOUT_FILENO)) {
        static const char resetSeq[] = "\033[r\033[?1l\033>\033[?25h\033[?1049l\033[?47l";
        static const char clearSeq[] = "\033[2J\033[H\r\n";
        (void)write(STDOUT_FILENO, resetSeq, sizeof(resetSeq) - 1);
        (void)write(STDOUT_FILENO, clearSeq, sizeof(clearSeq) - 1);
        (void)tcdrain(STDOUT_FILENO);
    }
    if (dupFd >= 0 && dupFd != STDIN_FILENO && dupFd != ttyFd) {
        close(dupFd);
    }

    microRestoreStandardFds(&stdioBackup);
#if defined(PSCAL_TARGET_IOS)
    if (hostBridgeActive) {
        microHostStdioBridgeTeardown(&hostBridge);
    }
    microBridgeMainThreadSet((pthread_t)0, false);
#endif
    free(patchedArgv);
    microRestoreEnvironment(&envBackup);
#if defined(PSCAL_TARGET_IOS)
    if (launchSlotAcquired) {
        microReleaseLaunchSlot();
    }
#endif
    return status;
}

#if defined(PSCAL_TARGET_IOS)
extern int pscal_micro_go_main_entry(int argc, char **argv);

int pscal_micro_main_entry(int argc, char **argv) {
    return pscal_micro_go_main_entry(argc, argv);
}
#endif
