#include "nextvi_app.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
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

// nextvi uses process-wide globals; serialize editor runs to avoid state races.
static pthread_mutex_t s_nextvi_lock = PTHREAD_MUTEX_INITIALIZER;

static char *smallclueOverrideEnv(const char *name, const char *value) {
    const char *current = getenv(name);
    char *saved = current ? strdup(current) : NULL;
    if (value) {
        setenv(name, value, 1);
    } else {
        unsetenv(name);
    }
    return saved;
}

static void smallclueRestoreEnv(const char *name, char *saved) {
    if (saved) {
        setenv(name, saved, 1);
        free(saved);
    } else {
        unsetenv(name);
    }
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

int smallclueRunEditor(int argc, char **argv) {
    const char *tool_name = (argc > 0 && argv && argv[0]) ? argv[0] : "nextvi";
    int lock_rc = pthread_mutex_trylock(&s_nextvi_lock);
    if (lock_rc != 0) {
        if (lock_rc == EBUSY) {
            fprintf(stderr, "%s: editor already running in another window\n", tool_name);
        } else {
            fprintf(stderr, "%s: unable to acquire editor lock (%d)\n", tool_name, lock_rc);
        }
        return 1;
    }
    /* nextvi expects xterm-ish behavior; advertise xterm-256color so SGR works. */
    char *saved_term = smallclueOverrideEnv("TERM", "xterm-256color");

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
    } else {
        have_tty = false;
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
    smallclueRestoreEnv("TERM", saved_term);
    pthread_mutex_unlock(&s_nextvi_lock);
    return status;
}
