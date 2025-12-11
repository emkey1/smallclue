#ifndef SMALLCLUE_PSCAL_OPENSSH_HOOKS_H
#define SMALLCLUE_PSCAL_OPENSSH_HOOKS_H

/*
 * Bridge header so the OpenSSH hook declarations are found in both layouts:
 * - PSCAL-integrated tree:   third-party/openssh-10.2p1/pscal_runtime_hooks.h
 * - Standalone smallclue:    third-party/openssh/pscal_runtime_hooks.h
 */
#if defined(__has_include)
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
