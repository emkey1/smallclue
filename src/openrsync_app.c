#include "openrsync_app.h"

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(PSCAL_TARGET_IOS)
#include <poll.h>
#include "ios/vproc.h"
#endif

#include "thread_getopt.h"

int pscal_openrsync_main(int argc, char **argv);

#ifndef SMALLCLUE_THREAD_LOCAL
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
    !defined(__STDC_NO_THREADS__)
#define SMALLCLUE_THREAD_LOCAL _Thread_local
#else
#define SMALLCLUE_THREAD_LOCAL __thread
#endif
#endif

typedef struct OpenrsyncExitContext {
    int exit_code;
    sigjmp_buf env;
    struct OpenrsyncExitContext *prev;
} OpenrsyncExitContext;

static SMALLCLUE_THREAD_LOCAL OpenrsyncExitContext *g_openrsync_exit_ctx = NULL;
static SMALLCLUE_THREAD_LOCAL const char *g_openrsync_progname = "rsync";

static const char *smallclueOpenrsyncLeafName(const char *path) {
    if (!path || !*path) {
        return "rsync";
    }
    const char *slash = strrchr(path, '/');
    if (!slash || !slash[1]) {
        return path;
    }
    return slash + 1;
}

const char *pscal_openrsync_getprogname(void) {
    if (!g_openrsync_progname || !*g_openrsync_progname) {
        return "rsync";
    }
    return g_openrsync_progname;
}

static void pscalOpenrsyncVreport(bool include_errno,
                                  int errnum,
                                  const char *fmt,
                                  va_list ap) {
    const char *prog = pscal_openrsync_getprogname();
    if (fmt && *fmt) {
        fprintf(stderr, "%s: ", prog);
        vfprintf(stderr, fmt, ap);
        if (include_errno) {
            fprintf(stderr, ": %s", strerror(errnum));
        }
        fputc('\n', stderr);
        return;
    }

    if (include_errno) {
        fprintf(stderr, "%s: %s\n", prog, strerror(errnum));
    } else {
        fprintf(stderr, "%s\n", prog);
    }
}

_Noreturn void pscal_openrsync_request_exit(int code) {
    if (g_openrsync_exit_ctx) {
        g_openrsync_exit_ctx->exit_code = code;
        siglongjmp(g_openrsync_exit_ctx->env, 1);
    }
    /* In the app this ends the thread; _Exit would end every terminal session. */
    exit(code);
}

_Noreturn void pscal_openrsync_err(int eval, const char *fmt, ...) {
    int saved_errno = errno;
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(true, saved_errno, fmt, ap);
    va_end(ap);
    pscal_openrsync_request_exit(eval);
}

_Noreturn void pscal_openrsync_errc(int eval, int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(true, code, fmt, ap);
    va_end(ap);
    pscal_openrsync_request_exit(eval);
}

_Noreturn void pscal_openrsync_errx(int eval, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(false, 0, fmt, ap);
    va_end(ap);
    pscal_openrsync_request_exit(eval);
}

void pscal_openrsync_warn(const char *fmt, ...) {
    int saved_errno = errno;
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(true, saved_errno, fmt, ap);
    va_end(ap);
}

void pscal_openrsync_warnc(int code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(true, code, fmt, ap);
    va_end(ap);
}

void pscal_openrsync_warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pscalOpenrsyncVreport(false, 0, fmt, ap);
    va_end(ap);
}

#if defined(PSCAL_TARGET_IOS)
static SMALLCLUE_THREAD_LOCAL volatile sig_atomic_t g_openrsync_interrupted = 0;

bool pscal_openrsync_interrupted(void) {
    return g_openrsync_interrupted != 0;
}

/* Runs on rsync's own thread, as a blocked poll returns with EINTR. */
static void smallclueOpenrsyncOnInterrupt(int signo) {
    (void)signo;
    g_openrsync_interrupted = 1;
}

/*
 * With pscal_ios_shim.h a file openrsync opens is a host descriptor, while its
 * socket to the other end is a vproc slot, and vprocPollShim calls the former
 * invalid. A file never blocks, so it is ready and the slots get no wait.
 */
int pscal_openrsync_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    VProc *vp = vprocCurrent();
    int saved[8];
    if (nfds > sizeof(saved) / sizeof(saved[0])) {
        errno = EINVAL;
        return -1;
    }
    int files = 0;
    for (nfds_t i = 0; i < nfds; ++i) {
        saved[i] = fds[i].fd;
        if (fds[i].fd >= 0 && vprocTranslateFd(vp, fds[i].fd) < 0) {
            fds[i].fd = -1;
            files++;
        }
    }
    int ready;
    do {
        ready = poll(fds, nfds, files > 0 ? 0 : timeout);
    } while (ready == -1 && errno == EINTR && !g_openrsync_interrupted);
    int saved_errno = errno;
    /* Even with something ready: ^C ends the ssh as well, and rsync then has an interrupt to
     * report, not a lost connection. */
    if (g_openrsync_interrupted) {
        ready = -1;
        saved_errno = EINTR;
    }
    for (nfds_t i = 0; i < nfds; ++i) {
        if (saved[i] != fds[i].fd) {
            fds[i].fd = saved[i];
            if (ready >= 0) {
                fds[i].revents = fds[i].events;
                ready++;
            }
        }
    }
    errno = saved_errno;
    return ready;
}
#endif

int smallclueRunRsync(int argc, char **argv) {
    OpenrsyncExitContext ctx;
    const char *prior_progname = g_openrsync_progname;

    if (argc > 0 && argv && argv[0]) {
        g_openrsync_progname = smallclueOpenrsyncLeafName(argv[0]);
    } else {
        g_openrsync_progname = "rsync";
    }

    ctx.exit_code = 1;
    ctx.prev = g_openrsync_exit_ctx;
    g_openrsync_exit_ctx = &ctx;

    /* The receiver zeroes the file mask and leaves it so, as a process about to exit may. A
     * command in a job or a pipeline stage runs on that task, which goes on after this. */
    mode_t prior_mask = umask(0);
    umask(prior_mask);
#if defined(PSCAL_TARGET_IOS)
    /* A command can share the shell's thread, so the signal's default action can't end this
     * one. Caught, it fails the transfer's next wait, and the command ends the way it would. */
    g_openrsync_interrupted = 0;
    struct sigaction on_interrupt;
    struct sigaction saved_interrupt;
    memset(&on_interrupt, 0, sizeof(on_interrupt));
    sigemptyset(&on_interrupt.sa_mask);
    on_interrupt.sa_handler = smallclueOpenrsyncOnInterrupt;
    bool caught = sigaction(SIGINT, &on_interrupt, &saved_interrupt) == 0;
#endif

    int status = 1;
    if (sigsetjmp(ctx.env, 1) == 0) {
        /* A local transfer's server gets here past the applet dispatcher. Zero is
         * what every libc's getopt takes as "start over". */
        optind = 0;
        status = pscal_openrsync_main(argc, argv);
    } else {
        status = ctx.exit_code;
    }

    umask(prior_mask);
#if defined(PSCAL_TARGET_IOS)
    if (caught) {
        (void)sigaction(SIGINT, &saved_interrupt, NULL);
    }
#endif

    g_openrsync_exit_ctx = ctx.prev;
    g_openrsync_progname = prior_progname;
    return status;
}
