#include "micro_app.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "termios_shim.h"
#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#endif

typedef struct {
    char *savedTerm;
    char *savedHome;
    char *savedXdgConfigHome;
    char *savedMicroConfigHome;
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

static void microPrepareEnvironment(MicroEnvBackup *backup) {
    if (!backup) {
        return;
    }
    memset(backup, 0, sizeof(*backup));
    backup->savedTerm = microDupEnv("TERM");
    backup->savedHome = microDupEnv("HOME");
    backup->savedXdgConfigHome = microDupEnv("XDG_CONFIG_HOME");
    backup->savedMicroConfigHome = microDupEnv("MICRO_CONFIG_HOME");

    setenv("TERM", "xterm-256color", 1);

#if defined(PSCAL_TARGET_IOS)
    char resolvedWorkdir[PATH_MAX];
    resolvedWorkdir[0] = '\0';
    const char *workdir = getenv("PSCALI_WORKDIR");
    if (!workdir || workdir[0] == '\0') {
        const char *containerRoot = getenv("PSCALI_CONTAINER_ROOT");
        if (containerRoot && containerRoot[0] == '/') {
            int wn = snprintf(resolvedWorkdir, sizeof(resolvedWorkdir), "%s/Documents/home", containerRoot);
            if (wn > 0 && (size_t)wn < sizeof(resolvedWorkdir)) {
                workdir = resolvedWorkdir;
            }
        }
    }
    if (workdir && workdir[0] == '/') {
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
    free(backup->savedTerm);
    free(backup->savedHome);
    free(backup->savedXdgConfigHome);
    free(backup->savedMicroConfigHome);
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
typedef struct {
    int read_fd;
    int write_fd;
    bool read_host;
    bool write_host;
} MicroIoBridgeThreadCtx;

typedef struct {
    bool active;
    int saved_host_stdin;
    int saved_host_stdout;
    int saved_host_stderr;
    int session_stdin;
    int session_stdout;
    int session_stderr;
    int pty_master;
    int pty_slave;
    pthread_t stdin_thread;
    pthread_t output_thread;
    bool stdin_thread_started;
    bool output_thread_started;
    MicroIoBridgeThreadCtx stdin_ctx;
    MicroIoBridgeThreadCtx output_ctx;
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
    bridge->session_stdin = -1;
    bridge->session_stdout = -1;
    bridge->session_stderr = -1;
    bridge->pty_master = -1;
    bridge->pty_slave = -1;
}

static void microHostCloseIfOpen(int *fd) {
    if (!fd || *fd < 0) {
        return;
    }
    (void)vprocHostClose(*fd);
    *fd = -1;
}

static void microCloseIfOpen(int *fd) {
    if (!fd || *fd < 0) {
        return;
    }
    (void)close(*fd);
    *fd = -1;
}

static ssize_t microIoBridgeRead(const MicroIoBridgeThreadCtx *ctx,
                                 void *buf,
                                 size_t count) {
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }
    if (ctx->read_host) {
        return vprocHostRead(ctx->read_fd, buf, count);
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
    return write(ctx->write_fd, buf, count);
}

static void *microIoBridgeThreadMain(void *opaque) {
    MicroIoBridgeThreadCtx *ctx = (MicroIoBridgeThreadCtx *)opaque;
    if (!ctx || ctx->read_fd < 0 || ctx->write_fd < 0) {
        return NULL;
    }
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    unsigned char buf[4096];
    for (;;) {
        ssize_t nr = microIoBridgeRead(ctx, buf, sizeof(buf));
        if (nr <= 0) {
            break;
        }
        size_t off = 0;
        while (off < (size_t)nr) {
            ssize_t nw = microIoBridgeWrite(ctx, buf + off, (size_t)nr - off);
            if (nw <= 0) {
                if (nw < 0 && (errno == EPIPE || errno == EIO || errno == EBADF)) {
                    return NULL;
                }
                return NULL;
            }
            off += (size_t)nw;
        }
    }
    return NULL;
}

static bool microHostStdioBridgeSetup(MicroHostStdioBridge *bridge) {
    if (!bridge) {
        return false;
    }
    microHostStdioBridgeInit(bridge);

    bridge->saved_host_stdin = vprocHostDup(STDIN_FILENO);
    bridge->saved_host_stdout = vprocHostDup(STDOUT_FILENO);
    bridge->saved_host_stderr = vprocHostDup(STDERR_FILENO);
    bridge->session_stdin = dup(STDIN_FILENO);
    bridge->session_stdout = dup(STDOUT_FILENO);
    bridge->session_stderr = dup(STDERR_FILENO);

    if (bridge->saved_host_stdin < 0 || bridge->saved_host_stdout < 0 || bridge->saved_host_stderr < 0 ||
        bridge->session_stdin < 0 || bridge->session_stdout < 0 || bridge->session_stderr < 0) {
        goto fail;
    }
    (void)fcntl(bridge->session_stdin, F_SETFD, FD_CLOEXEC);
    (void)fcntl(bridge->session_stdout, F_SETFD, FD_CLOEXEC);
    (void)fcntl(bridge->session_stderr, F_SETFD, FD_CLOEXEC);

    bridge->pty_master = vprocHostOpen("/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if (bridge->pty_master >= 0) {
        if (grantpt(bridge->pty_master) != 0 || unlockpt(bridge->pty_master) != 0) {
            goto fail;
        }
        char pty_slave_name[128];
        if (ptsname_r(bridge->pty_master, pty_slave_name, sizeof(pty_slave_name)) != 0) {
            goto fail;
        }
        bridge->pty_slave = vprocHostOpen(pty_slave_name, O_RDWR | O_NOCTTY, 0);
        if (bridge->pty_slave < 0) {
            goto fail;
        }
    } else {
        int sv[2] = { -1, -1 };
        if (vprocHostSocketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            goto fail;
        }
        bridge->pty_master = sv[0];
        bridge->pty_slave = sv[1];
        if (microDebugEnabled()) {
            fprintf(stderr,
                    "[micro-bridge] using socketpair fallback host=(%d,%d)\n",
                    bridge->pty_master,
                    bridge->pty_slave);
        }
    }

    if (vprocHostDup2(bridge->pty_slave, STDIN_FILENO) < 0 ||
        vprocHostDup2(bridge->pty_slave, STDOUT_FILENO) < 0 ||
        vprocHostDup2(bridge->pty_slave, STDERR_FILENO) < 0) {
        goto fail;
    }

    /* Feed micro stdin from the shell session stream. */
    bridge->stdin_ctx.read_fd = bridge->session_stdin;
    bridge->stdin_ctx.write_fd = bridge->pty_master;
    bridge->stdin_ctx.read_host = false;
    bridge->stdin_ctx.write_host = true;

    /* Route micro output back into the shell session stream (not host stdout). */
    bridge->output_ctx.read_fd = bridge->pty_master;
    bridge->output_ctx.write_fd = bridge->session_stdout;
    bridge->output_ctx.read_host = true;
    bridge->output_ctx.write_host = false;

    if (pthread_create(&bridge->stdin_thread, NULL, microIoBridgeThreadMain, &bridge->stdin_ctx) != 0) {
        goto fail;
    }
    bridge->stdin_thread_started = true;
    if (pthread_create(&bridge->output_thread, NULL, microIoBridgeThreadMain, &bridge->output_ctx) != 0) {
        goto fail;
    }
    bridge->output_thread_started = true;
    bridge->active = true;
    if (microDebugEnabled()) {
        fprintf(stderr,
                "[micro-bridge] setup ok host_saved=(%d,%d,%d) session_dup=(%d,%d,%d) host_pty=(m:%d s:%d)\n",
                bridge->saved_host_stdin,
                bridge->saved_host_stdout,
                bridge->saved_host_stderr,
                bridge->session_stdin,
                bridge->session_stdout,
                bridge->session_stderr,
                bridge->pty_master,
                bridge->pty_slave);
    }
    return true;

fail:
    if (microDebugEnabled()) {
        fprintf(stderr, "[micro-bridge] setup failed errno=%d\n", errno);
    }
    microHostStdioBridgeTeardown(bridge);
    return false;
}

static void microHostStdioBridgeTeardown(MicroHostStdioBridge *bridge) {
    if (!bridge) {
        return;
    }

    if (bridge->saved_host_stdin >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stdin, STDIN_FILENO);
    }
    if (bridge->saved_host_stdout >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stdout, STDOUT_FILENO);
    }
    if (bridge->saved_host_stderr >= 0) {
        (void)vprocHostDup2(bridge->saved_host_stderr, STDERR_FILENO);
    }

    if (bridge->stdin_thread_started) {
        microHostCloseIfOpen(&bridge->pty_slave);
        microHostCloseIfOpen(&bridge->pty_master);
        microCloseIfOpen(&bridge->session_stdin);
        (void)pthread_cancel(bridge->stdin_thread);
        (void)pthread_join(bridge->stdin_thread, NULL);
        bridge->stdin_thread_started = false;
    }
    if (bridge->output_thread_started) {
        microCloseIfOpen(&bridge->session_stdout);
        (void)pthread_cancel(bridge->output_thread);
        (void)pthread_join(bridge->output_thread, NULL);
        bridge->output_thread_started = false;
    }

    microHostCloseIfOpen(&bridge->pty_slave);
    microHostCloseIfOpen(&bridge->pty_master);
    microCloseIfOpen(&bridge->session_stdin);
    microCloseIfOpen(&bridge->session_stdout);
    microCloseIfOpen(&bridge->session_stderr);
    microHostCloseIfOpen(&bridge->saved_host_stdin);
    microHostCloseIfOpen(&bridge->saved_host_stdout);
    microHostCloseIfOpen(&bridge->saved_host_stderr);
    bridge->active = false;
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
    const char *enableBridge = getenv("PSCALI_MICRO_HOST_BRIDGE");
    bool bridgeRequested = true;
    if (enableBridge && strcmp(enableBridge, "0") == 0) {
        bridgeRequested = false;
    }
    if (bridgeRequested) {
        hostBridgeActive = microHostStdioBridgeSetup(&hostBridge);
    }
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
    if (haveTty) {
        struct termios raw = savedIos;
        raw.c_lflag &= ~(ICANON | ECHO | IEXTEN | ISIG);
        raw.c_iflag &= ~(ICRNL | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        smallclueTcsetattr(ttyFd, TCSAFLUSH, &raw);
        tcflush(ttyFd, TCIFLUSH);
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

    if (haveTty && savedIosValid) {
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
#endif
    free(patchedArgv);
    microRestoreEnvironment(&envBackup);
    return status;
}

#if defined(PSCAL_TARGET_IOS)
extern int pscal_micro_go_main_entry(int argc, char **argv);

int pscal_micro_main_entry(int argc, char **argv) {
    return pscal_micro_go_main_entry(argc, argv);
}
#endif
