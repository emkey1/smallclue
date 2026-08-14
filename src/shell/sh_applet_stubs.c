/* Stubs for smallclue applet dispatch, used ONLY when building the shell as
 * a standalone test binary (test_sh.sh). The real smallclue build links
 * src/core.c instead and must NOT include this file. */

#include "../smallclue.h"

#include <stddef.h>

const SmallclueApplet *smallclueFindApplet(const char *name) {
    (void)name;
    return NULL;
}

const SmallclueApplet *smallclueGetApplets(size_t *count) {
    if (count) {
        *count = 0;
    }
    return NULL;
}

int smallclueDispatchApplet(const SmallclueApplet *applet, int argc, char **argv) {
    (void)applet;
    (void)argc;
    (void)argv;
    return 127;
}
