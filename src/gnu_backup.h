/*
 * GNU's backup naming for cp, mv, ln and install: --backup[=CONTROL] and
 * -b (CONTROL from VERSION_CONTROL, else "existing"), -S SUFFIX (else
 * SIMPLE_BACKUP_SUFFIX, else "~"). Compiled once, in gnu_util.c.
 */
#ifndef SMALLCLUE_GNU_BACKUP_H
#define SMALLCLUE_GNU_BACKUP_H

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gnu_util.h"

typedef enum { GNU_BACKUP_NONE, GNU_BACKUP_SIMPLE, GNU_BACKUP_NUMBERED, GNU_BACKUP_EXISTING } GnuBackup;

/* NULL or "" means "existing", GNU's default. */
bool gnuBackupParse(const char *s, GnuBackup *out);

/* argmatch's complaint about a bad CONTROL; the caller adds its Try line. */
void gnuBackupComplain(const char *prog, const char *val);

/* The highest N among PATH.~N~ files, or 0. */
long gnuBackupHighest(const char *path);

/* The name PATH's backup gets; false when it does not fit. */
bool gnuBackupName(GnuBackup kind, const char *suffix, const char *path, char *out, size_t size);

const char *gnuBackupSuffix(const char *given);

#endif /* SMALLCLUE_GNU_BACKUP_H */
