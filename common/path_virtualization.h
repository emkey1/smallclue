#ifndef SMALLCLUE_PATH_VIRTUALIZATION_H
#define SMALLCLUE_PATH_VIRTUALIZATION_H

/* Platform-specific path virtualization hooks.
 * The standalone build does not virtualize paths, so the helper
 * always falls back to the original path.
 */
#include "path_truncate.h"

/* The host's name for a path the app has virtualized -- $HOME's /home, say --
 * written into BUFFER, which callers size at PATH_MAX. PSCAL defines the real
 * one; everywhere else there is nothing to translate, so the path comes back
 * as it went in.
 *
 * Returning the path rather than NULL is what the callers need: utmp_rec.c
 * assigns the result straight back over its own `path`. This fallback is the
 * thing the comment above has always promised and the header did not actually
 * provide, so a call outside a PSCAL_TARGET_IOS guard -- src/git_app.c has
 * one -- failed to compile in the standalone build and in iSH-AOK's. */
#if !defined(PSCAL_TARGET_IOS)
static inline const char *pscalPathVirtualized_hostPath(const char *path, char *buffer) {
    (void)buffer;
    return path;
}
#endif

#endif /* SMALLCLUE_PATH_VIRTUALIZATION_H */
