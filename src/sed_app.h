#ifndef SMALLCLUE_SED_APP_H
#define SMALLCLUE_SED_APP_H

int smallclueSedCommand(int argc, char **argv);

#if defined(PSCAL_TARGET_IOS)
/* One byte of stdin through SmallCLUE's own reader (core.c). */
int smallclueSedStdinGetc(int *out_errno);
#endif

#endif /* SMALLCLUE_SED_APP_H */
