/*
 * What core.c lends the applets kept in their own files: the embedding
 * host's file opening (PSCAL's path virtualisation on iOS) and its
 * cooperative interrupt check, for loops that would otherwise never end
 * (tail -f) when the applet runs as a function call.
 */
#ifndef SMALLCLUE_APP_HOOKS_H
#define SMALLCLUE_APP_HOOKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* fopen(path, "r") through the host's path translation. */
FILE *smallclueAppOpenRead(const char *path);
/* True when the command should stop (an interrupt); *status gets its exit
 * status. */
bool smallclueAppShouldAbort(int *status);
/* Forget interrupts that arrived before this command started. */
void smallclueAppClearPendingSignals(void);
/* Where the host cannot spawn an applet as a child (PSCAL on iOS), runs it
 * as a call: true, with its exit status in *status. Elsewhere false, and the
 * caller spawns it like any other program. */
bool smallclueAppRunInProcess(int argc, char **argv, int *status);
/* The executable `name` runs as, through the host's command lookup (PSCAL's
 * virtual paths on iOS); false to leave it to execvp. */
bool smallclueAppResolveExec(const char *name, char *resolved, size_t size);
/* Empty the environment, as env -i does. */
void smallclueAppClearEnv(void);

/* The applets are written for a plain POSIX host. On iOS the umbrella's CMake
 * force-includes this header into them, for what is different there. Absolute
 * paths are the app's virtual ones, so path calls go through path_virtualization.h.
 * A command's descriptors live in its vproc's table, not the host's. A pipeline or
 * redirection changes only the vproc's fd 0, so stdio's stdin, which reads the
 * host's, sees nothing: applets read through smallclueAppStdin. read, fstat, lseek
 * and dup are vproc shims that take table slots, while a stream from
 * smallclueAppOpenRead or fopen holds a host descriptor: fileno marks it as one.
 * ftruncate and futimens have no shim of their own elsewhere: a raw call would
 * reach whichever host descriptor has the slot's number. */
#if defined(PSCAL_TARGET_IOS) && !defined(VPROC_SHIM_DISABLED)
#include "common/path_virtualization.h"
FILE *smallclueAppStdin(void);
int smallclueAppFileno(FILE *stream);
#undef stdin
#define stdin smallclueAppStdin()
#undef fileno
#define fileno(stream) smallclueAppFileno(stream)
#undef ftruncate
#define ftruncate(fd, length) vprocFtruncateShim((fd), (length))
#undef futimens
#define futimens(fd, times) vprocFutimensShim((fd), (times))
#endif

#endif /* SMALLCLUE_APP_HOOKS_H */
