#ifndef SMALLCLUE_TERMIOS_SHIM_H
#define SMALLCLUE_TERMIOS_SHIM_H

#include <errno.h>
#include <termios.h>

#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#endif

static inline int smallclueTcgetattr(int fd, struct termios *termios) {
#if defined(PSCAL_TARGET_IOS)
    if (!termios) {
        errno = EINVAL;
        return -1;
    }
#if defined(TIOCGETA)
    if (vprocIoctlShim(fd, TIOCGETA, termios) == 0) {
        return 0;
    }
#elif defined(TCGETS)
    if (vprocIoctlShim(fd, TCGETS, termios) == 0) {
        return 0;
    }
#endif
#endif
    return tcgetattr(fd, termios);
}

static inline int smallclueTcsetattr(int fd, int action, const struct termios *termios) {
#if defined(PSCAL_TARGET_IOS)
    if (!termios) {
        errno = EINVAL;
        return -1;
    }
    unsigned long cmd = 0;
#if defined(TIOCSETA) && defined(TIOCSETAW) && defined(TIOCSETAF)
    switch (action) {
        case TCSANOW:
            cmd = TIOCSETA;
            break;
        case TCSADRAIN:
            cmd = TIOCSETAW;
            break;
        case TCSAFLUSH:
            cmd = TIOCSETAF;
            break;
    }
#elif defined(TCSETS) && defined(TCSETSW) && defined(TCSETSF)
    switch (action) {
        case TCSANOW:
            cmd = TCSETS;
            break;
        case TCSADRAIN:
            cmd = TCSETSW;
            break;
        case TCSAFLUSH:
            cmd = TCSETSF;
            break;
    }
#endif
    if (cmd != 0) {
        if (vprocIoctlShim(fd, cmd, (void *)termios) == 0) {
            return 0;
        }
    }
#endif
    return tcsetattr(fd, action, termios);
}

#endif /* SMALLCLUE_TERMIOS_SHIM_H */
