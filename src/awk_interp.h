#ifndef SMALLCLUE_AWK_INTERP_H
#define SMALLCLUE_AWK_INTERP_H

#include "awk_parser.h"

/* Runs a parsed AWK program: BEGIN blocks, then (if the program has any
 * main/END rules) reads records from the files/var=assignments in argv
 * (or stdin if none given), running matching rules per record, then END
 * blocks. `assigns` are -v NAME=VALUE pairs applied before BEGIN.
 * Returns the process exit code (0 normally, or whatever `exit N` set). */
int awkRunProgram(AwkProgram *prog, int argc, char **argv, int argStart,
                   char **preAssigns, int preAssignCount, const char *fsOverride);

#endif /* SMALLCLUE_AWK_INTERP_H */
