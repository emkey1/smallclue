#ifndef SMALLCLUE_SPAWN_H
#define SMALLCLUE_SPAWN_H

#include <stddef.h>
#include <sys/types.h>

/* Spawning a child, without assuming fork() exists.
 *
 * The applets here all used the same idiom: fork(), and in the child exec()
 * (sometimes several candidates in turn), report failure, _exit(127). That is
 * fine wherever fork() is available, but it cannot be implemented at all on a
 * platform that gives the whole program a single process -- AOK-Workstation compiles
 * smallclue in as host code inside one app process, so a child has to become a
 * real guest task instead, and there is no way for fork() to return twice into
 * C code that is not being duplicated.
 *
 * Expressing the idiom as "spawn a child running one of these argv vectors"
 * keeps the ordinary POSIX build byte-identical in behaviour while giving such
 * a platform a single function to implement.
 *
 * Callers keep their own waitpid()/kill() logic: this only replaces the
 * fork-and-exec half, because timeout(1) needs the pid to signal and init
 * needs it to reap.
 */

typedef struct {
    const char *file;      /* path, or bare name when search_path is set */
    char *const *argv;     /* NULL-terminated; argv[0] is what the child sees */
    int search_path;       /* nonzero: PATH search (execvp), else exact (execv) */
} SmallclueSpawnAttempt;

typedef struct {
    const SmallclueSpawnAttempt *attempts; /* tried in order until one execs */
    size_t attempt_count;
    int setpgid_self;      /* nonzero: child joins its own process group */
} SmallclueSpawnRequest;

/* Returns the child pid, or -1 with errno set.
 *
 * -1 means no attempt managed to exec -- distinct from the child running and
 * exiting nonzero, which is reported through the caller's own wait(). errno is
 * from the last attempt. Getting that distinction right is why the POSIX
 * implementation reports exec failure back over a close-on-exec pipe rather
 * than letting the caller infer it from exit status 127, which a legitimately
 * failing program could also produce.
 */
pid_t smallclueSpawn(const SmallclueSpawnRequest *request);

/* Convenience for the common single-attempt case. */
pid_t smallclueSpawnSimple(const char *file, char *const argv[], int search_path);

#endif /* SMALLCLUE_SPAWN_H */
