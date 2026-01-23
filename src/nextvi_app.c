#include "nextvi_app.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include "termios_shim.h"
#if defined(PSCAL_TARGET_IOS)
#include "common/path_virtualization.h"
#endif

extern int nextvi_main_entry(int argc, char **argv);
void nextvi_reset_state(void);

#if defined(PSCAL_TARGET_IOS)
void pscalRuntimeDebugLog(const char *message);
#else
static void pscalRuntimeDebugLog(const char *message) {
    (void)message;
}
#endif

// Track active editor sessions so we can block duplicate edits of the same file
// while still allowing different files to be open in other tabs/windows.
static pthread_mutex_t s_nextvi_sessions_lock = PTHREAD_MUTEX_INITIALIZER;
// Fallback single-instance guard for platforms that forbid fork().
static pthread_mutex_t s_nextvi_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    pid_t pid;
    char *path;  // canonicalized path; NULL when unknown
} NextviSession;

static NextviSession *s_nextvi_sessions = NULL;
static size_t s_nextvi_session_count = 0;
static size_t s_nextvi_session_cap = 0;

static void nextviFreeSession(NextviSession *session) {
    if (!session) {
        return;
    }
    free(session->path);
    session->path = NULL;
    session->pid = 0;
}

static bool nextviSessionPathExists(const char *path) {
    if (!path) {
        return false;
    }
    for (size_t i = 0; i < s_nextvi_session_count; ++i) {
        if (s_nextvi_sessions[i].path && strcmp(s_nextvi_sessions[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

static int nextviSessionEnsureCapacity(void) {
    if (s_nextvi_session_count < s_nextvi_session_cap) {
        return 0;
    }
    size_t new_cap = (s_nextvi_session_cap == 0) ? 4 : s_nextvi_session_cap * 2;
    NextviSession *resized = realloc(s_nextvi_sessions, new_cap * sizeof(NextviSession));
    if (!resized) {
        return -1;
    }
    // Zero new slots to keep free() safe.
    memset(resized + s_nextvi_session_cap, 0, (new_cap - s_nextvi_session_cap) * sizeof(NextviSession));
    s_nextvi_sessions = resized;
    s_nextvi_session_cap = new_cap;
    return 0;
}

static int nextviSessionRegister(const char *path, pid_t pid) {
    if (nextviSessionEnsureCapacity() != 0) {
        return -1;
    }
    NextviSession *slot = &s_nextvi_sessions[s_nextvi_session_count++];
    slot->pid = pid;
    slot->path = path ? strdup(path) : NULL;
    return (slot->path || !path) ? 0 : -1;
}

static void nextviSessionUnregisterByPid(pid_t pid) {
    for (size_t i = 0; i < s_nextvi_session_count; ++i) {
        if (s_nextvi_sessions[i].pid == pid) {
            nextviFreeSession(&s_nextvi_sessions[i]);
            // Compact array.
            if (i + 1 < s_nextvi_session_count) {
                s_nextvi_sessions[i] = s_nextvi_sessions[s_nextvi_session_count - 1];
            }
            --s_nextvi_session_count;
            return;
        }
    }
}

static char *smallclueCanonicalizePath(const char *input) {
    if (!input || !*input) {
        return NULL;
    }
    char resolved[PATH_MAX];
    if (realpath(input, resolved)) {
        return strdup(resolved);
    }
    // Fall back to building an absolute path if possible.
    if (input[0] == '/') {
        return strdup(input);
    }
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        char joined[PATH_MAX];
        int written = snprintf(joined, sizeof(joined), "%s/%s", cwd, input);
        if (written > 0 && written < (int)sizeof(joined)) {
            return strdup(joined);
        }
    }
    return strdup(input);
}

static char *smallclueDetectTargetPath(int argc, char **argv) {
    // Find the first non-option argument; treat it as the primary file.
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        // Skip flags (-x, -abc) and vi's +cmd.
        if (arg[0] == '-' || arg[0] == '+') {
            continue;
        }
        return smallclueCanonicalizePath(arg);
    }
    return NULL;
}

typedef struct {
    int saved_fds[3];
    bool saved_valid[3];
} SmallclueStdFdBackup;

static void smallclueSaveStandardFds(SmallclueStdFdBackup *backup) {
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

static void smallclueRestoreStandardFds(SmallclueStdFdBackup *backup) {
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

static void smallclueResetNextviGlobals(void) {
    /* nextvi_reset_state() is called inside nextvi_main_entry; avoid double-free */
}

#if defined(PSCAL_TARGET_IOS)
static int smallclueOpenPty(void) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) {
        return -1;
    }
    if (grantpt(master) != 0 || unlockpt(master) != 0) {
        close(master);
        return -1;
    }
    char slave_name[128];
    if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        close(master);
        return -1;
    }
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        close(master);
        return -1;
    }
    if (dup2(slave, STDIN_FILENO) < 0 ||
        dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0) {
        close(slave);
        close(master);
        return -1;
    }
    if (slave != STDIN_FILENO && slave != STDOUT_FILENO && slave != STDERR_FILENO) {
        close(slave);
    }
    close(master);
    return STDIN_FILENO;
}
#endif

static int smallclueSetupTty(void) {
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
#if defined(PSCAL_TARGET_IOS)
    if (fd < 0) {
        fd = smallclueOpenPty();
    }
#endif
    return fd;
}

static int smallclueRunEditorChild(int argc, char **argv) {
    /* nextvi expects xterm-ish behavior; advertise xterm-256color so SGR works. */
    const char *saved_term = getenv("TERM");
    setenv("TERM", "xterm-256color", 1);

    smallclueResetNextviGlobals();

    SmallclueStdFdBackup stdio_backup;
    smallclueSaveStandardFds(&stdio_backup);

    int dup_fd = smallclueSetupTty();
    struct termios saved_ios;
    int tty_fd = STDIN_FILENO;
    bool have_tty = false;
    if (smallclueTcgetattr(tty_fd, &saved_ios) != 0) {
        tty_fd = dup_fd >= 0 ? dup_fd : open("/dev/tty", O_RDWR);
        if (tty_fd >= 0 && smallclueTcgetattr(tty_fd, &saved_ios) == 0) {
            have_tty = true;
        }
    } else {
        have_tty = true;
    }
    if (have_tty) {
        struct termios raw = saved_ios;
        raw.c_lflag &= ~(ICANON | ECHO | IEXTEN | ISIG);
        raw.c_iflag &= ~(ICRNL | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        smallclueTcsetattr(tty_fd, TCSAFLUSH, &raw);
        tcflush(tty_fd, TCIFLUSH);
    }

    pscalRuntimeDebugLog("[smallclue] launching nextvi");
    int status = nextvi_main_entry(argc, argv);

    char resultBuf[128];
    snprintf(resultBuf, sizeof(resultBuf), "[smallclue] nextvi returned %d", status);
    pscalRuntimeDebugLog(resultBuf);

    if (have_tty) {
        smallclueTcsetattr(tty_fd, TCSAFLUSH, &saved_ios);
        if (tty_fd != STDIN_FILENO) {
            close(tty_fd);
        }
    }
    if (dup_fd >= 0 && dup_fd != STDIN_FILENO && dup_fd != tty_fd) {
        close(dup_fd);
    }
    smallclueRestoreStandardFds(&stdio_backup);
    if (saved_term) {
        setenv("TERM", saved_term, 1);
    } else {
        unsetenv("TERM");
    }
    return status;
}

int smallclueRunEditor(int argc, char **argv) {
    const char *tool_name = (argc > 0 && argv && argv[0]) ? argv[0] : "nextvi";

    // Identify target file and check for duplicate edit sessions.
    char *target_path = smallclueDetectTargetPath(argc, argv);
    pthread_mutex_lock(&s_nextvi_sessions_lock);
    if (target_path && nextviSessionPathExists(target_path)) {
        fprintf(stderr, "%s: %s is already open in another window\n", tool_name, target_path);
        pthread_mutex_unlock(&s_nextvi_sessions_lock);
        free(target_path);
        return 1;
    }
    pthread_mutex_unlock(&s_nextvi_sessions_lock);

    bool inline_fallback = false;
    pid_t child = fork();
    if (child < 0) {
        if (errno == EPERM || errno == ENOSYS) {
            inline_fallback = true;
        } else {
            perror("nextvi: fork");
            free(target_path);
            return 1;
        }
    }

    if (!inline_fallback && child == 0) {
        // Child: run the editor in isolation to avoid clobbering globals.
        int status = smallclueRunEditorChild(argc, argv);
        _exit(status);
    }

    if (inline_fallback) {
        // Single-process fallback: serialize via global lock.
        pthread_mutex_lock(&s_nextvi_lock);
    }

    // Parent: track the child session and wait for completion.
    bool registered = false;
    pthread_mutex_lock(&s_nextvi_sessions_lock);
    pid_t session_pid = inline_fallback ? getpid() : child;
    if (nextviSessionRegister(target_path, session_pid) == 0) {
        registered = true;
    } else {
        fprintf(stderr, "%s: unable to track editor session\n", tool_name);
    }
    pthread_mutex_unlock(&s_nextvi_sessions_lock);
    free(target_path);

    int exit_status = 0;
    if (inline_fallback) {
        exit_status = smallclueRunEditorChild(argc, argv);
    } else {
        int wstatus = 0;
        if (waitpid(child, &wstatus, 0) < 0) {
            perror("nextvi: waitpid");
        }
        if (WIFEXITED(wstatus)) {
            exit_status = WEXITSTATUS(wstatus);
        } else if (WIFSIGNALED(wstatus)) {
            int signo = WTERMSIG(wstatus);
            fprintf(stderr, "%s: terminated by signal %d\n", tool_name, signo);
            exit_status = 128 + signo;
        } else {
            exit_status = 1;
        }
    }

    if (registered) {
        pthread_mutex_lock(&s_nextvi_sessions_lock);
        nextviSessionUnregisterByPid(session_pid);
        pthread_mutex_unlock(&s_nextvi_sessions_lock);
    }

    if (inline_fallback) {
        pthread_mutex_unlock(&s_nextvi_lock);
    }
    return exit_status;
}
