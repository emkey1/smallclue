#include "openrsync_app.h"

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    _Exit(code);
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

    int status = 1;
    if (sigsetjmp(ctx.env, 1) == 0) {
        status = pscal_openrsync_main(argc, argv);
    } else {
        status = ctx.exit_code;
    }

    g_openrsync_exit_ctx = ctx.prev;
    g_openrsync_progname = prior_progname;
    return status;
}
