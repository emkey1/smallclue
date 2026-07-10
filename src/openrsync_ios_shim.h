#ifndef SMALLCLUE_OPENRSYNC_IOS_SHIM_H
#define SMALLCLUE_OPENRSYNC_IOS_SHIM_H

#ifdef PSCAL_TARGET_IOS
/*
 * openrsync sources already get vproc_shim.h via global build flags.
 * pscal_ios_shim.h defines overlapping libc macro redirects; undefine
 * prior mappings first so we can cleanly switch to the OpenSSH iOS shim
 * implementations for fork/exec/read/write plumbing.
 */
#ifdef read
#undef read
#endif
#ifdef open
#undef open
#endif
#ifdef openat
#undef openat
#endif
#ifdef write
#undef write
#endif
#ifdef fprintf
#undef fprintf
#endif
#ifdef printf
#undef printf
#endif
#ifdef fputs
#undef fputs
#endif
#ifdef puts
#undef puts
#endif
#ifdef close
#undef close
#endif
#ifdef pipe
#undef pipe
#endif
#ifdef socket
#undef socket
#endif
#ifdef socketpair
#undef socketpair
#endif
#ifdef dup
#undef dup
#endif
#ifdef dup2
#undef dup2
#endif
#ifdef fcntl
#undef fcntl
#endif
#ifdef closefrom
#undef closefrom
#endif
#ifdef ioctl
#undef ioctl
#endif
#ifdef tcgetattr
#undef tcgetattr
#endif
#ifdef tcsetattr
#undef tcsetattr
#endif
#ifdef isatty
#undef isatty
#endif
#ifdef fstat
#undef fstat
#endif
#ifdef stat
#undef stat
#endif
#ifdef lstat
#undef lstat
#endif
#ifdef access
#undef access
#endif
#ifdef faccessat
#undef faccessat
#endif
#ifdef utimes
#undef utimes
#endif
#ifdef futimes
#undef futimes
#endif
#ifdef chdir
#undef chdir
#endif
#ifdef getcwd
#undef getcwd
#endif
#ifdef fopen
#undef fopen
#endif
#ifdef opendir
#undef opendir
#endif
#ifdef mkdir
#undef mkdir
#endif
#ifdef rmdir
#undef rmdir
#endif
#ifdef unlink
#undef unlink
#endif
#ifdef remove
#undef remove
#endif
#ifdef rename
#undef rename
#endif
#ifdef link
#undef link
#endif
#ifdef symlink
#undef symlink
#endif
#ifdef pthread_create
#undef pthread_create
#endif

#include "pscal_ios_shim.h"
#endif /* PSCAL_TARGET_IOS */

#endif /* SMALLCLUE_OPENRSYNC_IOS_SHIM_H */
