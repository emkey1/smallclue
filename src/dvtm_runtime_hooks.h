#ifndef SMALLCLUE_DVTM_RUNTIME_HOOKS_H
#define SMALLCLUE_DVTM_RUNTIME_HOOKS_H

#include <setjmp.h>

typedef struct DvtmExitContext {
    int exit_code;
    sigjmp_buf env;
    struct DvtmExitContext *prev;
} DvtmExitContext;

void smallclueDvtmPushExitContext(DvtmExitContext *ctx);
void smallclueDvtmPopExitContext(DvtmExitContext *ctx);
_Noreturn void pscalDvtmRequestExit(int code);

#endif /* SMALLCLUE_DVTM_RUNTIME_HOOKS_H */
