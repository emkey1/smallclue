#include "nextvi_app.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
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

typedef struct {
    pthread_t thread;
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
    session->thread = (pthread_t)0;
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

static void nextviSessionUnregisterByThread(pthread_t thread) {
    for (size_t i = 0; i < s_nextvi_session_count; ++i) {
        if (pthread_equal(s_nextvi_sessions[i].thread, thread)) {
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

static void nextviSessionRemoveIndex(size_t idx) {
    if (idx >= s_nextvi_session_count) {
        return;
    }
    nextviFreeSession(&s_nextvi_sessions[idx]);
    if (idx + 1 < s_nextvi_session_count) {
        s_nextvi_sessions[idx] = s_nextvi_sessions[s_nextvi_session_count - 1];
    }
    --s_nextvi_session_count;
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

typedef struct {
    int argc;
    char **argv;
} NextviThreadArgs;

static char **smallclueCopyArgv(int argc, char **argv) {
    if (argc <= 0 || !argv) {
        return NULL;
    }
    char **copy = calloc((size_t)argc + 1, sizeof(char *));
    if (!copy) {
        return NULL;
    }
    for (int i = 0; i < argc; ++i) {
        if (argv[i]) {
            copy[i] = strdup(argv[i]);
            if (!copy[i]) {
                for (int j = 0; j < i; ++j) {
                    free(copy[j]);
                }
                free(copy);
                return NULL;
            }
        }
    }
    copy[argc] = NULL;
    return copy;
}

static void smallclueFreeThreadArgs(NextviThreadArgs *args) {
    if (!args) {
        return;
    }
    if (args->argv) {
        for (int i = 0; i < args->argc; ++i) {
            free(args->argv[i]);
        }
        free(args->argv);
    }
    free(args);
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
    bool saved_ios_valid = false;
    int tty_fd = STDIN_FILENO;
    bool have_tty = false;
    if (smallclueTcgetattr(tty_fd, &saved_ios) != 0) {
        tty_fd = dup_fd >= 0 ? dup_fd : open("/dev/tty", O_RDWR);
        if (tty_fd >= 0 && smallclueTcgetattr(tty_fd, &saved_ios) == 0) {
            have_tty = true;
            saved_ios_valid = true;
        }
    } else {
        have_tty = true;
        saved_ios_valid = true;
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

    if (have_tty && saved_ios_valid) {
        /* Restore both the descriptor we toggled and STDIN_FILENO in case they differ. */
        smallclueTcsetattr(tty_fd, TCSAFLUSH, &saved_ios);
        if (tty_fd != STDIN_FILENO) {
            smallclueTcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_ios);
        }
        tcflush(STDIN_FILENO, TCIOFLUSH);
        tcflush(tty_fd, TCIOFLUSH);
        if (tty_fd != STDIN_FILENO) {
            close(tty_fd);
        }
    }
    if (isatty(STDOUT_FILENO)) {
        /* Reset scroll region, cursor keys, cursor visibility, exit alt screens, and clear display. */
        static const char reset_seq[] = "\033[r\033[?1l\033>\033[?25h\033[?1049l\033[?47l";
        static const char clear_seq[] = "\033[2J\033[H\r\n";
        (void)write(STDOUT_FILENO, reset_seq, sizeof(reset_seq) - 1);
        (void)write(STDOUT_FILENO, clear_seq, sizeof(clear_seq) - 1);
        (void)tcdrain(STDOUT_FILENO);
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

static void *smallclueRunEditorThread(void *opaque) {
    NextviThreadArgs *args = (NextviThreadArgs *)opaque;
    (void)smallclueRunEditorChild(args->argc, args->argv);

    pthread_mutex_lock(&s_nextvi_sessions_lock);
    nextviSessionUnregisterByThread(pthread_self());
    pthread_mutex_unlock(&s_nextvi_sessions_lock);

    smallclueFreeThreadArgs(args);
    return NULL;
}

int smallclueRunEditor(int argc, char **argv) {
#if defined(SMALLCLUE_NEXTVI_DIRECT)
    /*
     * iSH kernels can expose partial futex behavior for some pthread paths.
     * Run nextvi directly in the caller thread to avoid pthread_create/join.
     */
    return smallclueRunEditorChild(argc, argv);
#else
    const char *tool_name = (argc > 0 && argv && argv[0]) ? argv[0] : "nextvi";

    NextviThreadArgs *args = calloc(1, sizeof(*args));
    if (!args) {
        fprintf(stderr, "%s: unable to allocate editor args\n", tool_name);
        return 1;
    }
    args->argc = argc;
    args->argv = smallclueCopyArgv(argc, argv);
    if (!args->argv) {
        fprintf(stderr, "%s: unable to copy argv\n", tool_name);
        smallclueFreeThreadArgs(args);
        return 1;
    }

    // Identify target file and reserve a session slot to block duplicates.
    char *target_path = smallclueDetectTargetPath(argc, argv);
    pthread_mutex_lock(&s_nextvi_sessions_lock);
    if (target_path && nextviSessionPathExists(target_path)) {
        fprintf(stderr, "%s: %s is already open in another window\n", tool_name, target_path);
        pthread_mutex_unlock(&s_nextvi_sessions_lock);
        smallclueFreeThreadArgs(args);
        free(target_path);
        return 1;
    }

    if (nextviSessionEnsureCapacity() != 0) {
        fprintf(stderr, "%s: unable to track editor session\n", tool_name);
        pthread_mutex_unlock(&s_nextvi_sessions_lock);
        smallclueFreeThreadArgs(args);
        free(target_path);
        return 1;
    }

    size_t slot_idx = s_nextvi_session_count++;
    s_nextvi_sessions[slot_idx].thread = (pthread_t)0;
    s_nextvi_sessions[slot_idx].path = target_path;
    target_path = NULL;

    pthread_t tid;

    /* nextvi uses a regex-based highlighter that can recurse deeply; the default
     * pthread stack on iOS is small (~512 KB) and can overflow on modest files.
     * Bump the stack to 2 MB to avoid crashes when opening larger documents. */
    pthread_attr_t attr;
    int attr_init_res = pthread_attr_init(&attr);
    if (attr_init_res == 0) {
        size_t stack_size = 2 * 1024 * 1024; /* 2 MB */
        if (stack_size < PTHREAD_STACK_MIN) {
            stack_size = PTHREAD_STACK_MIN;
        }
        (void)pthread_attr_setstacksize(&attr, stack_size);
    }

    int create_res = pthread_create(&tid,
                                    (attr_init_res == 0 ? &attr : NULL),
                                    smallclueRunEditorThread,
                                    args);
    if (attr_init_res == 0) {
        (void)pthread_attr_destroy(&attr);
    }
    if (create_res != 0) {
        fprintf(stderr, "%s: unable to start editor thread (%s)\n", tool_name, strerror(create_res));
        nextviSessionRemoveIndex(slot_idx);
        pthread_mutex_unlock(&s_nextvi_sessions_lock);
        smallclueFreeThreadArgs(args);
        return 1;
    }

    s_nextvi_sessions[slot_idx].thread = tid;
    pthread_mutex_unlock(&s_nextvi_sessions_lock);

    /* Block until the editor thread finishes so the caller's TTY is not reused prematurely. */
    (void)pthread_join(tid, NULL);
    return 0;
#endif
}
