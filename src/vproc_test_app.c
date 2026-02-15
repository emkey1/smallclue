#include "smallclue.h"
#include <stdio.h>

#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

char *read_passphrase(const char *prompt, int flags);

typedef struct {
    int failures;
} VprocTestState;

static bool gVprocTestDebug = false;

static bool vprocTestDebugEnabled(void) {
    return gVprocTestDebug;
}

typedef enum {
    VPROC_TEST_FAIL = 0,
    VPROC_TEST_OK,
    VPROC_TEST_SKIP
} VprocTestResult;

static void vprocTestNote(VprocTestState *state,
                          const char *label,
                          VprocTestResult result,
                          const char *detail) {
    if (result == VPROC_TEST_OK) {
        fprintf(stderr, "ok: %s\n", label);
        return;
    }
    if (result == VPROC_TEST_SKIP) {
        if (detail && detail[0]) {
            fprintf(stderr, "skip: %s (%s)\n", label, detail);
        } else {
            fprintf(stderr, "skip: %s\n", label);
        }
        return;
    }
    if (detail && detail[0]) {
        fprintf(stderr, "fail: %s (%s)\n", label, detail);
    } else {
        fprintf(stderr, "fail: %s\n", label);
    }
    if (state) {
        state->failures++;
    }
}

static VprocTestResult vprocTestSessionReady(const char **detail) {
    VProcSessionInput *input = vprocSessionInputEnsureShim();
    if (!input) {
        if (detail) {
            *detail = "no session input";
        }
        return VPROC_TEST_FAIL;
    }
    pthread_mutex_lock(&input->mu);
    bool busy = (input->len != 0);
    bool eof = input->eof;
    pthread_mutex_unlock(&input->mu);
    if (eof) {
        if (detail) {
            *detail = "session eof";
        }
        return VPROC_TEST_FAIL;
    }
    if (busy) {
        if (detail) {
            *detail = "pending input";
        }
        return VPROC_TEST_SKIP;
    }
    return VPROC_TEST_OK;
}

static VprocTestResult vprocTestSessionRead(const char *payload, const char **detail) {
    if (!payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }
    VprocTestResult ready = vprocTestSessionReady(detail);
    if (ready != VPROC_TEST_OK) {
        return ready;
    }
    size_t len = strlen(payload);
    if (!vprocSessionInjectInputShim(payload, len)) {
        if (detail) {
            *detail = "inject failed";
        }
        return VPROC_TEST_FAIL;
    }
    char *buf = (char *)calloc(len + 1, 1);
    if (!buf) {
        if (detail) {
            *detail = "alloc failed";
        }
        return VPROC_TEST_FAIL;
    }
    ssize_t n = vprocSessionReadInputShim(buf, len);
    bool ok = (n == (ssize_t)len && memcmp(buf, payload, len) == 0);
    free(buf);
    return ok ? VPROC_TEST_OK : VPROC_TEST_FAIL;
}

static VprocTestResult vprocTestVprocRead(const char *payload, const char **detail) {
    if (!payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }
    int pipefd[2];
    if (vprocHostPipe(pipefd) != 0) {
        if (detail) {
            *detail = "pipe failed";
        }
        return VPROC_TEST_FAIL;
    }
    size_t len = strlen(payload);
    ssize_t w = vprocHostWrite(pipefd[1], payload, len);
    vprocHostClose(pipefd[1]);
    if (w != (ssize_t)len) {
        vprocHostClose(pipefd[0]);
        if (detail) {
            *detail = "pipe write failed";
        }
        return VPROC_TEST_FAIL;
    }
    VProcOptions opts = vprocDefaultOptions();
    opts.stdin_fd = pipefd[0];
    VProc *vp = vprocCreate(&opts);
    if (!vp) {
        vprocHostClose(pipefd[0]);
        if (detail) {
            *detail = "vproc create failed";
        }
        return VPROC_TEST_FAIL;
    }
    vprocRegisterThread(vp, pthread_self());
    vprocActivate(vp);

    char *buf = (char *)calloc(len + 1, 1);
    if (!buf) {
        vprocDeactivate();
        vprocDestroy(vp);
        vprocHostClose(pipefd[0]);
        if (detail) {
            *detail = "alloc failed";
        }
        return VPROC_TEST_FAIL;
    }
    size_t total = 0;
    while (total < len) {
        ssize_t r = vprocReadShim(STDIN_FILENO, buf + total, len - total);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
    }
    vprocDeactivate();
    vprocDestroy(vp);
    vprocHostClose(pipefd[0]);

    bool ok = (total == len && memcmp(buf, payload, len) == 0);
    free(buf);
    return ok ? VPROC_TEST_OK : VPROC_TEST_FAIL;
}

int pscalVprocTestChildMain(int argc, char **argv) {
    const char *mode = getenv("PSCAL_VPROC_TEST_CHILD_MODE");
    if (mode && strcmp(mode, "authprompt") == 0) {
        (void)argc;
        (void)argv;
        char *pass = read_passphrase("vproc-test-child password:", 0);
        if (!pass || pass[0] == '\0') {
            if (pass) {
                free(pass);
            }
            fprintf(stderr, "[vproc-test-child] empty\n");
            return 91;
        }
        fprintf(stderr, "[vproc-test-child] accepted len=%zu\n", strlen(pass));
        free(pass);
        /* Non-zero keeps scp from claiming transfer success; this shim is for
         * stdin/prompt regression coverage only. */
        return 92;
    } else if (mode && strcmp(mode, "authprompt_hold") == 0) {
        (void)argc;
        (void)argv;
        char *pass = read_passphrase("vproc-test-child password:", 0);
        if (!pass || pass[0] == '\0') {
            if (pass) {
                free(pass);
            }
            fprintf(stderr, "[vproc-test-child] empty\n");
            return 91;
        }
        fprintf(stderr, "[vproc-test-child] accepted len=%zu\n", strlen(pass));
        free(pass);
        /* Keep stdin open and drain incoming bytes so scp does not exit
         * immediately on protocol I/O while prompt-path tests run. */
        for (;;) {
            unsigned char sink = 0;
            ssize_t rd = read(STDIN_FILENO, &sink, 1);
            if (rd == 0) {
                break;
            }
            if (rd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
        }
        return 93;
    }
    return 0;
}

typedef struct {
    const char *payload;
    size_t len;
} VprocSpawnCtx;

typedef struct {
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    bool valid;
} VprocTestSessionBackup;

static void vprocTestSessionClearInput(VProcSessionStdio *session);

typedef struct {
    int fd;
    const char *payload;
    size_t len;
    int delay_ms;
    bool ok;
    int err;
} VprocTestWriteCtx;

typedef struct {
    const char *payload;
    size_t len;
    int delay_ms;
    bool ok;
} VprocTestInjectCtx;

static int vprocTestDupFd(int fd) {
    if (fd < 0) {
        return -1;
    }
    int duped = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (duped < 0 && errno == EINVAL) {
        duped = fcntl(fd, F_DUPFD, 0);
    }
    if (duped < 0) {
        duped = vprocHostDup(fd);
    }
    if (duped >= 0) {
        fcntl(duped, F_SETFD, FD_CLOEXEC);
    }
    return duped;
}

static bool vprocTestSessionBackup(VProcSessionStdio *session,
                                   VprocTestSessionBackup *backup,
                                   const char **detail) {
    if (!session || !backup) {
        if (detail) {
            *detail = "no session";
        }
        return false;
    }
    backup->stdin_fd = vprocTestDupFd(session->stdin_host_fd);
    backup->stdout_fd = vprocTestDupFd(session->stdout_host_fd);
    backup->stderr_fd = vprocTestDupFd(session->stderr_host_fd);
    backup->valid = true;
    if (session->stdin_host_fd >= 0 && backup->stdin_fd < 0) {
        backup->valid = false;
        if (detail) {
            *detail = "dup stdin failed";
        }
    } else if (session->stdout_host_fd >= 0 && backup->stdout_fd < 0) {
        backup->valid = false;
        if (detail) {
            *detail = "dup stdout failed";
        }
    } else if (session->stderr_host_fd >= 0 && backup->stderr_fd < 0) {
        backup->valid = false;
        if (detail) {
            *detail = "dup stderr failed";
        }
    }
    if (!backup->valid) {
        if (backup->stdin_fd >= 0) {
            vprocHostClose(backup->stdin_fd);
        }
        if (backup->stdout_fd >= 0) {
            vprocHostClose(backup->stdout_fd);
        }
        if (backup->stderr_fd >= 0) {
            vprocHostClose(backup->stderr_fd);
        }
        backup->stdin_fd = -1;
        backup->stdout_fd = -1;
        backup->stderr_fd = -1;
    }
    return backup->valid;
}

static void vprocTestSessionStopReader(VProcSessionStdio *session) {
    if (!session || !session->input) {
        return;
    }
    VProcSessionInput *input = session->input;
    pthread_mutex_lock(&input->mu);
    bool active = input->reader_active;
    input->stop_requested = true;
    pthread_cond_broadcast(&input->cv);
    pthread_mutex_unlock(&input->mu);

    if (active && session->stdin_host_fd >= 0) {
        vprocHostClose(session->stdin_host_fd);
        session->stdin_host_fd = -1;
    }

    pthread_mutex_lock(&input->mu);
    while (input->reader_active) {
        pthread_cond_wait(&input->cv, &input->mu);
    }
    input->stop_requested = false;
    input->eof = false;
    input->len = 0;
    input->interrupt_pending = false;
    input->reader_fd = -1;
    pthread_mutex_unlock(&input->mu);
}

static void vprocTestSessionRestore(VProcSessionStdio *session,
                                    VprocTestSessionBackup *backup) {
    if (!session || !backup || !backup->valid) {
        return;
    }
    if (session->input) {
        vprocTestSessionStopReader(session);
    }
    if (session->stdin_host_fd >= 0) {
        vprocHostClose(session->stdin_host_fd);
    }
    if (session->stdout_host_fd >= 0) {
        vprocHostClose(session->stdout_host_fd);
    }
    if (session->stderr_host_fd >= 0) {
        vprocHostClose(session->stderr_host_fd);
    }
    session->stdin_host_fd = backup->stdin_fd;
    session->stdout_host_fd = backup->stdout_fd;
    session->stderr_host_fd = backup->stderr_fd;
    backup->stdin_fd = -1;
    backup->stdout_fd = -1;
    backup->stderr_fd = -1;
    backup->valid = false;

    vprocTestSessionClearInput(session);
    (void)vprocSessionInputEnsureShim();
}

static void vprocTestSessionReplaceStdin(VProcSessionStdio *session, int stdin_fd) {
    if (!session) {
        return;
    }
    if (session->input) {
        vprocTestSessionStopReader(session);
    }
    if (session->stdin_host_fd >= 0) {
        vprocHostClose(session->stdin_host_fd);
    }
    session->stdin_host_fd = stdin_fd;
}

static void vprocTestSessionClearInput(VProcSessionStdio *session) {
    if (!session || !session->input) {
        return;
    }
    pthread_mutex_lock(&session->input->mu);
    session->input->len = 0;
    session->input->eof = false;
    session->input->interrupt_pending = false;
    pthread_cond_broadcast(&session->input->cv);
    pthread_mutex_unlock(&session->input->mu);
}

static void *vprocTestWritePipe(void *arg) {
    VprocTestWriteCtx *ctx = (VprocTestWriteCtx *)arg;
    if (!ctx) {
        return NULL;
    }
    ctx->ok = true;
    ctx->err = 0;
    if (ctx->delay_ms > 0) {
        usleep((useconds_t)ctx->delay_ms * 1000);
    }
    if (ctx->payload && ctx->len > 0) {
        ssize_t wrote = vprocHostWrite(ctx->fd, ctx->payload, ctx->len);
        if (wrote < 0 || (size_t)wrote != ctx->len) {
            ctx->ok = false;
            ctx->err = errno;
        }
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] write payload fd=%d rc=%zd errno=%d\n",
                    ctx->fd,
                    wrote,
                    errno);
        }
        wrote = vprocHostWrite(ctx->fd, "\n", 1);
        if (wrote != 1 && ctx->ok) {
            ctx->ok = false;
            ctx->err = errno;
        }
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] write newline fd=%d rc=%zd errno=%d\n",
                    ctx->fd,
                    wrote,
                    errno);
        }
    }
    vprocHostClose(ctx->fd);
    return NULL;
}

static void *vprocTestInjectInput(void *arg) {
    VprocTestInjectCtx *ctx = (VprocTestInjectCtx *)arg;
    if (!ctx) {
        return NULL;
    }
    if (ctx->delay_ms > 0) {
        usleep((useconds_t)ctx->delay_ms * 1000);
    }
    ctx->ok = vprocSessionInjectInputShim(ctx->payload, ctx->len);
    if (ctx->ok) {
        ctx->ok = vprocSessionInjectInputShim("\n", 1);
    }
    return NULL;
}

static void vprocTestDumpEntry(int pid, int waiter_pid) {
    if (!vprocTestDebugEnabled()) {
        return;
    }
    VProcSnapshot snap[64];
    size_t count = vprocSnapshot(snap, sizeof(snap) / sizeof(snap[0]));
    const VProcSnapshot *found = NULL;
    for (size_t i = 0; i < count; ++i) {
        if (snap[i].pid == pid) {
            found = &snap[i];
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "[vproc-test] snapshot missing pid=%d waiter=%d\n",
                pid, waiter_pid);
        return;
    }
    fprintf(stderr,
            "[vproc-test] snapshot pid=%d parent=%d waiter=%d exited=%d zombie=%d stop=%d status=%d sigchld=%d\n",
            found->pid,
            found->parent_pid,
            waiter_pid,
            (int)found->exited,
            (int)found->zombie,
            (int)found->stopped,
            found->status,
            (int)found->sigchld_pending);
}

static void vprocTestDrainSessionInput(size_t len) {
    if (len == 0) {
        return;
    }
    char buf[64];
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t n = vprocSessionReadInputShim(buf, chunk);
        if (n <= 0) {
            break;
        }
        remaining -= (size_t)n;
    }
}

static void *vprocTestSpawnChild(void *arg) {
    VprocSpawnCtx *ctx = (VprocSpawnCtx *)arg;
    const char *payload = ctx ? ctx->payload : NULL;
    size_t len = ctx ? ctx->len : 0;
    free(ctx);

    if (!payload || len == 0) {
        return (void *)(intptr_t)1;
    }

    char *buf = (char *)calloc(len + 1, 1);
    if (!buf) {
        return (void *)(intptr_t)1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t r = vprocReadShim(STDIN_FILENO, buf + total, len - total);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
    }

    bool ok = (total == len && memcmp(buf, payload, len) == 0);
    free(buf);
    return (void *)(intptr_t)(ok ? 0 : 1);
}

static VprocTestResult vprocTestSpawnExec(const char *payload, const char **detail) {
    if (!payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }

    VprocTestResult ready = vprocTestSessionReady(detail);
    if (ready != VPROC_TEST_OK) {
        return ready;
    }

    size_t len = strlen(payload);
    if (!vprocSessionInjectInputShim(payload, len)) {
        if (detail) {
            *detail = "inject failed";
        }
        return VPROC_TEST_FAIL;
    }

    VProcSessionStdio *session = vprocSessionStdioCurrent();
    VProcOptions opts = vprocDefaultOptions();
    if (session && session->stdin_host_fd >= 0) {
        opts.stdin_fd = session->stdin_host_fd;
    }
    VProc *vp = vprocCreate(&opts);
    if (!vp) {
        vprocTestDrainSessionInput(len);
        if (detail) {
            *detail = "vproc create failed";
        }
        return VPROC_TEST_FAIL;
    }

    int parent_pid = vprocGetPidShim();
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] spawn parent_pid=%d shell=%d kernel=%d child=%d\n",
                parent_pid,
                vprocGetShellSelfPid(),
                vprocGetKernelPid(),
                vprocPid(vp));
    }
    if (parent_pid > 0 && parent_pid != vprocPid(vp)) {
        vprocSetParent(vprocPid(vp), parent_pid);
    }
    vprocTestDumpEntry(vprocPid(vp), parent_pid);

    VprocSpawnCtx *ctx = (VprocSpawnCtx *)calloc(1, sizeof(VprocSpawnCtx));
    if (!ctx) {
        vprocDestroy(vp);
        if (detail) {
            *detail = "alloc failed";
        }
        return VPROC_TEST_FAIL;
    }
    ctx->payload = payload;
    ctx->len = len;

    pthread_t thread = 0;
    if (vprocSpawnThread(vp, vprocTestSpawnChild, ctx, &thread) != 0) {
        free(ctx);
        vprocTestDrainSessionInput(len);
        vprocDestroy(vp);
        if (detail) {
            *detail = strerror(errno);
        }
        return VPROC_TEST_FAIL;
    }

    bool ok = false;
    int status = 0;
    int waited = 0;
    int child_pid = vprocPid(vp);
    int waiter_pid = (int)vprocGetPidShim();
    while (waited < 1000) {
        pid_t rc = vprocWaitPidShim(child_pid, &status, WNOHANG);
        if (rc == child_pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                ok = true;
            }
            break;
        }
        if (rc < 0) {
            break;
        }
        usleep(10000);
        waited += 10;
    }

    pthread_join(thread, NULL);
    vprocDestroy(vp);

    if (!ok) {
        if (waited >= 1000 && detail) {
            *detail = "timeout";
        } else if (detail && *detail == NULL) {
            if (WIFEXITED(status)) {
                static char msg[32];
                snprintf(msg, sizeof(msg), "exit=%d", WEXITSTATUS(status));
                *detail = msg;
            } else if (WIFSIGNALED(status)) {
                static char msg[32];
                snprintf(msg, sizeof(msg), "signal=%d", WTERMSIG(status));
                *detail = msg;
            }
        }
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] spawn wait status=%d waited=%d errno=%d\n",
                    status,
                    waited,
                    errno);
        }
        vprocTestDumpEntry(child_pid, waiter_pid);
    }

    return ok ? VPROC_TEST_OK : VPROC_TEST_FAIL;
}

static VprocTestResult vprocTestReadPassphrase(const char *payload,
                                               const char **detail) {
    if (!payload || !*payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }

    char *pass = read_passphrase("vproc-test passphrase:", 0);
    if (!pass) {
        if (detail) {
            *detail = "read failed";
        }
        return VPROC_TEST_FAIL;
    }
    if (pass[0] == '\0') {
        free(pass);
        if (detail) {
            *detail = "empty";
        }
        return VPROC_TEST_FAIL;
    }
    VprocTestResult result = (strcmp(pass, payload) == 0) ? VPROC_TEST_OK : VPROC_TEST_FAIL;
    if (result != VPROC_TEST_OK && detail) {
        *detail = "mismatch";
    }
    free(pass);
    return result;
}

static VprocTestResult vprocTestReadPassPipe(const char *payload, const char **detail) {
    if (!payload || !*payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }
    VProcSessionStdio *session = vprocSessionStdioCurrent();
    VprocTestSessionBackup backup = {.stdin_fd = -1, .stdout_fd = -1, .stderr_fd = -1, .valid = false};
    if (!vprocTestSessionBackup(session, &backup, detail)) {
        return VPROC_TEST_FAIL;
    }

    int pipefd[2];
    if (vprocHostPipe(pipefd) != 0) {
        vprocTestSessionRestore(session, &backup);
        if (detail) {
            *detail = "pipe failed";
        }
        return VPROC_TEST_FAIL;
    }

    int session_stdin = vprocTestDupFd(pipefd[0]);
    if (session_stdin < 0) {
        vprocHostClose(pipefd[0]);
        vprocHostClose(pipefd[1]);
        vprocTestSessionRestore(session, &backup);
        if (detail) {
            *detail = "dup pipe failed";
        }
        return VPROC_TEST_FAIL;
    }
    int hold_fd = vprocTestDupFd(pipefd[1]);
    if (vprocTestDebugEnabled()) {
        fprintf(stderr, "[vproc-test] pipe hold=%d\n", hold_fd);
    }

    vprocTestSessionReplaceStdin(session, session_stdin);
    vprocTestSessionClearInput(session);
    (void)vprocSessionInputEnsureShim();

    VProcOptions opts = vprocDefaultOptions();
    opts.stdin_fd = pipefd[0];
    VProc *vp = vprocCreate(&opts);
    if (!vp) {
        vprocHostClose(pipefd[0]);
        vprocHostClose(pipefd[1]);
        if (hold_fd >= 0) {
            vprocHostClose(hold_fd);
        }
        vprocTestSessionRestore(session, &backup);
        if (detail) {
            *detail = "vproc create failed";
        }
        return VPROC_TEST_FAIL;
    }

    vprocRegisterThread(vp, pthread_self());
    vprocActivate(vp);
    vprocHostClose(pipefd[0]);
    if (vprocTestDebugEnabled()) {
        int vproc_stdin = vprocTranslateFd(vp, STDIN_FILENO);
        fprintf(stderr,
                "[vproc-test] pipe read=%d write=%d session_stdin=%d vproc_stdin=%d\n",
                pipefd[0],
                pipefd[1],
                session_stdin,
                vproc_stdin);
    }

    VprocTestWriteCtx *ctx = (VprocTestWriteCtx *)calloc(1, sizeof(VprocTestWriteCtx));
    pthread_t writer = 0;
    bool writer_started = false;
    size_t payload_len = strlen(payload);
    if (ctx) {
        ctx->fd = pipefd[1];
        ctx->payload = payload;
        ctx->len = payload_len;
        ctx->delay_ms = 50;
        if (vprocHostPthreadCreate(&writer, NULL, vprocTestWritePipe, ctx) == 0) {
            writer_started = true;
        } else if (vprocTestDebugEnabled()) {
            fprintf(stderr, "[vproc-test] writer spawn failed\n");
        } else {
            vprocTestWritePipe(ctx);
        }
    } else {
        (void)vprocHostWrite(pipefd[1], payload, payload_len);
        (void)vprocHostWrite(pipefd[1], "\n", 1);
        vprocHostClose(pipefd[1]);
    }

    VprocTestResult result = vprocTestReadPassphrase(payload, detail);

    if (writer_started) {
        pthread_join(writer, NULL);
    }
    if (ctx) {
        if (!ctx->ok && result == VPROC_TEST_OK) {
            result = VPROC_TEST_FAIL;
            if (detail) {
                *detail = "write failed";
            }
        }
        free(ctx);
    }
    if (hold_fd >= 0) {
        vprocHostClose(hold_fd);
    }

    vprocDeactivate();
    vprocDestroy(vp);
    vprocTestSessionRestore(session, &backup);

    return result;
}

static VprocTestResult vprocTestReadPassInject(const char *payload, const char **detail) {
    if (!payload || !*payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }

    VProcSessionInput *input = vprocSessionInputEnsureShim();
    if (!input) {
        if (detail) {
            *detail = "no session input";
        }
        return VPROC_TEST_FAIL;
    }
    if (vprocTestDebugEnabled()) {
        pthread_mutex_lock(&input->mu);
        fprintf(stderr,
                "[vproc-test] inject input len=%zu eof=%d reader=%d fd=%d\n",
                input->len,
                (int)input->eof,
                (int)input->reader_active,
                input->reader_fd);
        pthread_mutex_unlock(&input->mu);
    }

    VprocTestInjectCtx *ctx = (VprocTestInjectCtx *)calloc(1, sizeof(VprocTestInjectCtx));
    pthread_t writer = 0;
    bool writer_started = false;
    size_t payload_len = strlen(payload);
    if (ctx) {
        ctx->payload = payload;
        ctx->len = payload_len;
        ctx->delay_ms = 50;
        if (vprocHostPthreadCreate(&writer, NULL, vprocTestInjectInput, ctx) == 0) {
            writer_started = true;
        } else {
            vprocTestInjectInput(ctx);
        }
    }

    VprocTestResult result = vprocTestReadPassphrase(payload, detail);

    if (writer_started) {
        pthread_join(writer, NULL);
    }
    if (ctx) {
        if (!ctx->ok && result == VPROC_TEST_OK) {
            result = VPROC_TEST_FAIL;
            if (detail) {
                *detail = "inject failed";
            }
        }
        free(ctx);
    }

    vprocTestSessionClearInput(vprocSessionStdioCurrent());
    return result;
}

typedef struct {
    const char *payload;
    size_t payload_len;
    bool ok;
    int err;
    char seen[32];
    size_t seen_len;
} VprocTestReadPassChildCtx;

typedef struct {
    VProc *vp;
    VprocTestReadPassChildCtx *child;
    int shell_pid;
    int kernel_pid;
} VprocTestReadPassThreadCtx;

static void *vprocTestReadPassChild(void *arg) {
    VprocTestReadPassChildCtx *ctx = (VprocTestReadPassChildCtx *)arg;
    if (!ctx || !ctx->payload || ctx->payload_len == 0) {
        if (ctx) {
            ctx->err = EINVAL;
            ctx->ok = false;
        }
        return NULL;
    }
    char *pass = read_passphrase("vproc-test passphrase:", 0);
    if (!pass || pass[0] == '\0') {
        ctx->err = EIO;
        ctx->ok = false;
        fprintf(stderr, "[vproc-test] readpass empty\n");
        free(pass);
        return NULL;
    }
    if (strcmp(pass, ctx->payload) == 0) {
        ctx->ok = true;
        ctx->err = 0;
    } else {
        ctx->ok = false;
        ctx->err = EINVAL;
        size_t copy_len = strlen(pass);
        if (copy_len >= sizeof(ctx->seen)) {
            copy_len = sizeof(ctx->seen) - 1;
        }
        if (copy_len > 0) {
            memcpy(ctx->seen, pass, copy_len);
        }
        ctx->seen[copy_len] = '\0';
        ctx->seen_len = strlen(pass);
        fprintf(stderr,
                "[vproc-test] readpass mismatch len=%zu buf=\"%s\"\n",
                ctx->seen_len,
                ctx->seen);
    }
    free(pass);
    return NULL;
}

static void *vprocTestReadPassThreadMain(void *arg) {
    VprocTestReadPassThreadCtx *ctx = (VprocTestReadPassThreadCtx *)arg;
    bool activated = false;
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass thread start vp=%p shell=%d kernel=%d\n",
                ctx ? (void *)ctx->vp : NULL,
                ctx ? ctx->shell_pid : -1,
                ctx ? ctx->kernel_pid : -1);
    }
    if (ctx && ctx->vp) {
        if (ctx->shell_pid > 0) {
            vprocSetShellSelfPid(ctx->shell_pid);
        }
        if (ctx->kernel_pid > 0) {
            vprocSetKernelPid(ctx->kernel_pid);
        }
        vprocActivate(ctx->vp);
        vprocRegisterThread(ctx->vp, pthread_self());
        activated = true;
    }
    if (ctx && ctx->child) {
        vprocTestReadPassChild(ctx->child);
    }
    if (activated) {
        vprocUnregisterThread(ctx->vp, pthread_self());
        vprocDeactivate();
    }
    if (vprocTestDebugEnabled()) {
        fprintf(stderr, "[vproc-test] readpass thread done\n");
    }
    return NULL;
}

static VprocTestResult vprocTestReadPassSpawn(const char *payload, const char **detail) {
    if (!payload || !*payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }

    VprocTestResult ready = vprocTestSessionReady(detail);
    if (ready != VPROC_TEST_OK) {
        return ready;
    }

    VProcSessionStdio *session = vprocSessionStdioCurrent();
    if (!session) {
        if (detail) {
            *detail = "no session";
        }
        return VPROC_TEST_FAIL;
    }
    vprocTestSessionClearInput(session);
    (void)vprocSessionInputEnsureShim();

    VProc *vp = vprocCurrent();
    if (!vp) {
        if (detail) {
            *detail = "no vproc";
        }
        return VPROC_TEST_FAIL;
    }

    VprocTestReadPassChildCtx ctx = {
        .payload = payload,
        .payload_len = strlen(payload),
        .ok = false,
        .err = 0,
        .seen = {0},
        .seen_len = 0
    };
    pthread_t thread = 0;
    VprocTestReadPassThreadCtx thread_ctx = {
        .vp = vp,
        .child = &ctx,
        .shell_pid = vprocGetShellSelfPid(),
        .kernel_pid = vprocGetKernelPid()
    };
    bool thread_started = (pthread_create(&thread, NULL, vprocTestReadPassThreadMain,
                                          &thread_ctx) == 0);

    VprocTestInjectCtx *write_ctx = (VprocTestInjectCtx *)calloc(1, sizeof(VprocTestInjectCtx));
    pthread_t writer = 0;
    bool writer_started = false;
    if (write_ctx) {
        write_ctx->payload = payload;
        write_ctx->len = ctx.payload_len;
        write_ctx->delay_ms = 50;
        if (vprocHostPthreadCreate(&writer, NULL, vprocTestInjectInput, write_ctx) == 0) {
            writer_started = true;
        } else {
            vprocTestInjectInput(write_ctx);
        }
    } else {
        VprocTestInjectCtx fallback = {
            .payload = payload,
            .len = ctx.payload_len,
            .delay_ms = 0
        };
        vprocTestInjectInput(&fallback);
    }

    if (!thread_started) {
        vprocTestReadPassChild(&ctx);
    }
    if (writer_started) {
        pthread_join(writer, NULL);
    }
    if (write_ctx) {
        if (!write_ctx->ok && ctx.ok) {
            ctx.ok = false;
            ctx.err = EIO;
        }
        free(write_ctx);
    }

    if (thread_started) {
        pthread_join(thread, NULL);
    }
    vprocTestSessionClearInput(session);

    if (!ctx.ok) {
        if (detail) {
            *detail = (ctx.err == EINVAL) ? "mismatch" : "read failed";
        }
        return VPROC_TEST_FAIL;
    }
    return VPROC_TEST_OK;
}

static VprocTestResult vprocTestReadPassVproc(const char *payload, const char **detail) {
    if (!payload || !*payload) {
        if (detail) {
            *detail = "no payload";
        }
        return VPROC_TEST_FAIL;
    }

    fprintf(stderr,
            "[vproc-test] readpass_vproc start dbg=%d\n",
            vprocTestDebugEnabled() ? 1 : 0);
    VprocTestResult ready = vprocTestSessionReady(detail);
    if (ready != VPROC_TEST_OK) {
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] readpass_vproc not ready result=%d detail=%s\n",
                    (int)ready,
                    (detail && *detail) ? *detail : "none");
        }
        return ready;
    }

    VProcSessionStdio *session = vprocSessionStdioCurrent();
    if (!session) {
        if (detail) {
            *detail = "no session";
        }
        return VPROC_TEST_FAIL;
    }
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass_vproc session stdin=%d stdout=%d stderr=%d input=%p\n",
                session->stdin_host_fd,
                session->stdout_host_fd,
                session->stderr_host_fd,
                (void *)session->input);
    }
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass_vproc enter stdin=%d stdout=%d stderr=%d\n",
                session->stdin_host_fd,
                session->stdout_host_fd,
                session->stderr_host_fd);
    }
    vprocTestSessionClearInput(session);
    (void)vprocSessionInputEnsureShim();

    VProcOptions opts = vprocDefaultOptions();
    if (session->stdin_host_fd >= 0) {
        opts.stdin_fd = session->stdin_host_fd;
    }
    if (session->stdout_host_fd >= 0) {
        opts.stdout_fd = session->stdout_host_fd;
    }
    if (session->stderr_host_fd >= 0) {
        opts.stderr_fd = session->stderr_host_fd;
    }
    VProc *vp = vprocCreate(&opts);
    if (!vp) {
        if (detail) {
            *detail = "vproc create failed";
        }
        return VPROC_TEST_FAIL;
    }
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass_vproc vproc pid=%d stdin=%d\n",
                vprocPid(vp),
                vprocTranslateFd(vp, STDIN_FILENO));
    }

    int parent_pid = vprocGetPidShim();
    if (parent_pid > 0 && parent_pid != vprocPid(vp)) {
        vprocSetParent(vprocPid(vp), parent_pid);
    }
    int fg_sid = -1;
    int fg_prev = -1;
    if (parent_pid > 0) {
        fg_sid = vprocGetSid(parent_pid);
        if (fg_sid > 0) {
            fg_prev = vprocGetForegroundPgid(fg_sid);
            if (fg_prev > 0) {
                (void)vprocSetpgidShim(vprocPid(vp), vprocPid(vp));
                if (vprocSetForegroundPgid(fg_sid, vprocPid(vp)) != 0 &&
                    vprocTestDebugEnabled()) {
                    fprintf(stderr,
                            "[vproc-test] readpass_vproc fg set failed sid=%d pgid=%d errno=%d\n",
                            fg_sid,
                            vprocPid(vp),
                            errno);
                } else if (vprocTestDebugEnabled()) {
                    fprintf(stderr,
                            "[vproc-test] readpass_vproc fg sid=%d prev=%d now=%d\n",
                            fg_sid,
                            fg_prev,
                            vprocPid(vp));
                }
            } else if (vprocTestDebugEnabled()) {
                fprintf(stderr,
                        "[vproc-test] readpass_vproc fg skip sid=%d prev=%d\n",
                        fg_sid,
                        fg_prev);
            }
        }
    }

    VprocTestReadPassChildCtx ctx = {
        .payload = payload,
        .payload_len = strlen(payload),
        .ok = false,
        .err = 0,
        .seen = {0},
        .seen_len = 0
    };
    pthread_t thread = 0;
    VprocTestReadPassThreadCtx thread_ctx = {
        .vp = vp,
        .child = &ctx,
        .shell_pid = vprocGetShellSelfPid(),
        .kernel_pid = vprocGetKernelPid()
    };
    int thread_rc = vprocHostPthreadCreate(&thread, NULL, vprocTestReadPassThreadMain, &thread_ctx);
    bool thread_started = (thread_rc == 0);
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass_vproc thread rc=%d started=%d\n",
                thread_rc,
                (int)thread_started);
    }

    VprocTestInjectCtx inject_ctx = {
        .payload = payload,
        .len = ctx.payload_len,
        .delay_ms = 50,
        .ok = false
    };
    vprocTestInjectInput(&inject_ctx);
    if (vprocTestDebugEnabled()) {
        fprintf(stderr,
                "[vproc-test] readpass_vproc injected ok=%d\n",
                (int)inject_ctx.ok);
    }

    if (!thread_started) {
        vprocActivate(vp);
        vprocRegisterThread(vp, pthread_self());
        vprocTestReadPassChild(&ctx);
        vprocUnregisterThread(vp, pthread_self());
        vprocDeactivate();
    }
    if (!inject_ctx.ok && ctx.ok) {
        ctx.ok = false;
        ctx.err = EIO;
    }

    if (thread_started) {
        pthread_join(thread, NULL);
    }
    if (fg_sid > 0 && fg_prev > 0) {
        (void)vprocSetForegroundPgid(fg_sid, fg_prev);
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] readpass_vproc fg restore sid=%d pgid=%d\n",
                    fg_sid,
                    fg_prev);
        }
    }
    vprocDestroy(vp);
    vprocTestSessionClearInput(session);

    if (!ctx.ok) {
        if (vprocTestDebugEnabled()) {
            fprintf(stderr,
                    "[vproc-test] readpass_vproc err=%d seen_len=%zu seen=\"%s\"\n",
                    ctx.err,
                    ctx.seen_len,
                    ctx.seen);
        }
        if (detail) {
            *detail = (ctx.err == EINVAL) ? "mismatch" : "read failed";
        }
        return VPROC_TEST_FAIL;
    }
    return VPROC_TEST_OK;
}
#endif

#if !defined(PSCAL_TARGET_IOS)
#include <stdio.h>
#endif

int smallclueVprocTestCommand(int argc, char **argv) {
#if !defined(PSCAL_TARGET_IOS)
    (void)argc;
    (void)argv;
    fprintf(stderr, "vproc-test: only available on iOS/iPadOS builds.\n");
    return 1;
#else
    gVprocTestDebug = (getenv("PSCALI_TOOL_DEBUG") != NULL);
    if (vprocTestDebugEnabled()) {
#ifdef PROGRAM_VERSION
        fprintf(stderr, "[vproc-test] build=%s\n", PROGRAM_VERSION);
#else
        fprintf(stderr, "[vproc-test] build=unknown\n");
#endif
        fprintf(stderr, "[vproc-test] marker=%s %s\n", __DATE__, __TIME__);
    }
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        fprintf(stderr,
                "vproc-test [--help]\n"
                "  Run vproc/session/spawn diagnostics.\n"
                "  --session  Only run session input checks.\n"
                "  --vproc    Only run vproc stdin checks.\n"
                "  --spawn    Only run vproc spawn checks.\n"
                "  --readpass Run SSH-style passphrase read tests.\n"
                "  --fork     Alias for --spawn (fork unsupported on iOS).\n");
        return 0;
    }
    bool run_session = true;
    bool run_vproc = true;
    bool run_spawn = true;
    bool run_readpass = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--session") == 0) {
            run_session = true;
            run_vproc = false;
            run_spawn = false;
            run_readpass = false;
        } else if (strcmp(argv[i], "--vproc") == 0) {
            run_session = false;
            run_vproc = true;
            run_spawn = false;
            run_readpass = false;
        } else if (strcmp(argv[i], "--spawn") == 0 || strcmp(argv[i], "--fork") == 0) {
            run_session = false;
            run_vproc = false;
            run_spawn = true;
            run_readpass = false;
        } else if (strcmp(argv[i], "--readpass") == 0) {
            run_session = false;
            run_vproc = false;
            run_spawn = false;
            run_readpass = true;
        } else if (strcmp(argv[i], "--no-spawn") == 0 || strcmp(argv[i], "--no-fork") == 0) {
            run_spawn = false;
        }
    }

    VprocTestState state = {0};
    const char *detail = NULL;
    VprocTestResult result;
    if (run_session) {
        fprintf(stderr, "start: session_read\n");
        fflush(stderr);
        result = vprocTestSessionRead("hello\n", &detail);
        vprocTestNote(&state, "session_read", result, detail);
    }
    detail = NULL;
    if (run_vproc) {
        fprintf(stderr, "start: vproc_read\n");
        fflush(stderr);
        result = vprocTestVprocRead("pipe\n", &detail);
        vprocTestNote(&state, "vproc_read", result, detail);
    }
    detail = NULL;
    if (run_spawn) {
        fprintf(stderr, "start: spawn_exec\n");
        fflush(stderr);
        result = vprocTestSpawnExec("child\n", &detail);
        vprocTestNote(&state, "spawn_exec", result, detail);
    }
    detail = NULL;
    if (run_readpass) {
        fprintf(stderr, "start: readpass_pipe\n");
        fflush(stderr);
        result = vprocTestReadPassPipe("secret", &detail);
        vprocTestNote(&state, "readpass_pipe", result, detail);
        fprintf(stderr, "start: readpass_inject\n");
        fflush(stderr);
        result = vprocTestReadPassInject("secret", &detail);
        vprocTestNote(&state, "readpass_inject", result, detail);
        fprintf(stderr, "start: readpass_spawn\n");
        fflush(stderr);
        result = vprocTestReadPassSpawn("secret", &detail);
        vprocTestNote(&state, "readpass_spawn", result, detail);
        fprintf(stderr, "start: readpass_vproc\n");
        fflush(stderr);
        result = vprocTestReadPassVproc("secret", &detail);
        vprocTestNote(&state, "readpass_vproc", result, detail);
    }
    if (state.failures) {
        fprintf(stderr, "vproc-test: %d failure(s)\n", state.failures);
        return 1;
    }
    fprintf(stderr, "vproc-test: ok\n");
    return 0;
#endif
}
