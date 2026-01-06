#ifndef SMALLCLUE_SMALLCLUE_H
#define SMALLCLUE_SMALLCLUE_H

#include <stddef.h>
#include <stdbool.h>
#if defined(PSCAL_TARGET_IOS)
#include "common/path_virtualization.h"
/* Ensure vproc syscall shims apply in app builds that skip global -include. */
#include "ios/vproc_shim.h"
#endif

#if defined(__APPLE__) || defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define SMALLCLUE_HAS_IFADDRS 1
#else
#define SMALLCLUE_HAS_IFADDRS 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*SmallclueAppletEntry)(int argc, char **argv);

typedef struct SmallclueApplet {
    const char *name;
    SmallclueAppletEntry entry;
    const char *description;
} SmallclueApplet;

int smallclueMain(int argc, char **argv);

const SmallclueApplet *smallclueGetApplets(size_t *count);
const SmallclueApplet *smallclueFindApplet(const char *name);
int smallclueDispatchApplet(const SmallclueApplet *applet, int argc, char **argv);

void smallclueRegisterBuiltins(void);
bool smallclueIsRegisteredBuiltinName(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* SMALLCLUE_SMALLCLUE_H */
