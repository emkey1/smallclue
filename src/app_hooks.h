/*
 * What core.c lends the applets kept in their own files: the embedding
 * host's file opening (PSCAL's path virtualisation on iOS) and its
 * cooperative interrupt check, for loops that would otherwise never end
 * (tail -f) when the applet runs as a function call.
 */
#ifndef SMALLCLUE_APP_HOOKS_H
#define SMALLCLUE_APP_HOOKS_H

#include <stdbool.h>
#include <stdio.h>

/* fopen(path, "r") through the host's path translation. */
FILE *smallclueAppOpenRead(const char *path);
/* True when the command should stop (an interrupt); *status gets its exit
 * status. */
bool smallclueAppShouldAbort(int *status);
/* Forget interrupts that arrived before this command started. */
void smallclueAppClearPendingSignals(void);

#endif /* SMALLCLUE_APP_HOOKS_H */
