#include "spawn.h"

#include "app_hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#endif

/* A platform without fork() supplies its own implementation and defines
 * SMALLCLUE_PLATFORM_SPAWN. iSH-AOK does this: a child there is a real guest
 * task, created through the kernel's own task machinery, not a host process. */
#ifdef SMALLCLUE_PLATFORM_SPAWN
extern pid_t smallcluePlatformSpawn(const SmallclueSpawnRequest *request);
#endif

pid_t smallclueSpawn(const SmallclueSpawnRequest *request) {
    if (request == NULL || request->attempts == NULL || request->attempt_count == 0) {
        errno = EINVAL;
        return -1;
    }

#ifdef SMALLCLUE_PLATFORM_SPAWN
    return smallcluePlatformSpawn(request);
#elif defined(PSCAL_TARGET_IOS) && !defined(VPROC_SHIM_DISABLED)
    /* The app is one process, and a real fork would leave the shim's waitpid with no
     * child it knows. A child is a thread with a vproc of its own instead, which the
     * shim's waitpid and kill treat as any other. There is no exec to fail in the child,
     * so a name that cannot run is reported here. */
    errno = ENOENT;
    for (size_t i = 0; i < request->attempt_count; i++) {
        const SmallclueSpawnAttempt *a = &request->attempts[i];
        if (a->file == NULL || a->argv == NULL || !smallclueAppCanRun(a->file))
            continue;
        return vprocSpawnEntry(a->file, !request->setpgid_self, smallclueAppChildMain, a->argv);
    }
    return -1;
#else
    /* Close-on-exec pipe: the child writes its errno into it only if every
     * exec fails, so a successful exec closes it empty and the parent can tell
     * "never started" from "started and exited 127". */
    int failpipe[2];
    if (pipe(failpipe) < 0)
        return -1;
    if (fcntl(failpipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        int saved = errno;
        close(failpipe[0]);
        close(failpipe[1]);
        errno = saved;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int saved = errno;
        close(failpipe[0]);
        close(failpipe[1]);
        errno = saved;
        return -1;
    }

    if (pid == 0) {
        close(failpipe[0]);
        if (request->setpgid_self)
            (void) setpgid(0, 0);
        for (size_t i = 0; i < request->attempt_count; i++) {
            const SmallclueSpawnAttempt *a = &request->attempts[i];
            if (a->file == NULL || a->argv == NULL)
                continue;
            if (a->search_path)
                (void) execvp(a->file, a->argv);
            else
                (void) execv(a->file, a->argv);
        }
        int err = errno;
        (void) !write(failpipe[1], &err, sizeof(err));
        _exit(127);
    }

    close(failpipe[1]);
    int child_errno = 0;
    ssize_t got = read(failpipe[0], &child_errno, sizeof(child_errno));
    close(failpipe[0]);
    if (got == (ssize_t) sizeof(child_errno)) {
        /* Reap the child that never became the program, so the caller's own
         * wait() does not collect a status for something that never ran. */
        int discard;
        while (waitpid(pid, &discard, 0) < 0 && errno == EINTR)
            ;
        errno = child_errno;
        return -1;
    }
    return pid;
#endif
}

pid_t smallclueSpawnSimple(const char *file, char *const argv[], int search_path) {
    SmallclueSpawnAttempt attempt = { file, argv, search_path };
    SmallclueSpawnRequest request = { &attempt, 1, 0 };
    return smallclueSpawn(&request);
}
