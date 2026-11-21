#ifndef SMALLCLUE_IP_APP_H
#define SMALLCLUE_IP_APP_H

#include <stdio.h>

int smallclueIpCommand(int argc, char **argv);

/* The command against a given snapshot (a PscalNetSnapshot *), writing to out and
 * err, so a test can check what it prints for interfaces it made up. */
int smallclueIpRun(int argc, char **argv, const void *snapshot, FILE *out, FILE *err);

#endif /* SMALLCLUE_IP_APP_H */
