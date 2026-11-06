#ifndef SMALLCLUE_PSCAL_OPENSSH_HOOKS_H
#define SMALLCLUE_PSCAL_OPENSSH_HOOKS_H

/*
 * Bridge header so the OpenSSH hook declarations are found in both layouts:
 * - PSCAL-integrated tree:   PSCAL's CMake names the header of the OpenSSH
 *                            tree it builds in PSCAL_OPENSSH_HOOKS_HEADER, so
 *                            an OpenSSH upgrade there needs no change here.
 * - Standalone smallclue:    third-party/openssh/pscal_runtime_hooks.h
 * Never fall back to smallclue's own copy inside PSCAL: that is another
 * OpenSSH, and its hooks need not match the one being linked.
 */
#if defined(PSCAL_OPENSSH_HOOKS_HEADER)
#  include PSCAL_OPENSSH_HOOKS_HEADER
#elif defined(__has_include)
#  if __has_include("../../third-party/openssh-10.2p1/pscal_runtime_hooks.h")
#    include "../../third-party/openssh-10.2p1/pscal_runtime_hooks.h"
#  elif __has_include("../third-party/openssh/pscal_runtime_hooks.h")
#    include "../third-party/openssh/pscal_runtime_hooks.h"
#  else
#    error "pscal_runtime_hooks.h not found; adjust include path for OpenSSH hooks."
#  endif
#else
#  include "../third-party/openssh/pscal_runtime_hooks.h"
#endif

#endif /* SMALLCLUE_PSCAL_OPENSSH_HOOKS_H */
