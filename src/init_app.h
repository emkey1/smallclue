#ifndef SMALLCLUE_INIT_APP_H
#define SMALLCLUE_INIT_APP_H

#include <stdbool.h>
#include <stddef.h>

int smallclueInitCommand(int argc, char **argv);
int smallclueHaltCommand(int argc, char **argv);
int smallclueRunitCommand(int argc, char **argv);
int smallclueSvCommand(int argc, char **argv);

/* From core.c: /etc/<name> (or PSCAL's relocated etc), and exsh. */
bool smallclueResolveEtcEntry(const char *entryName, int accessMode,
                              char *outPath, size_t outPathSize);
bool smallclueResolveExshPath(char *outPath, size_t outPathSize);

#endif /* SMALLCLUE_INIT_APP_H */
