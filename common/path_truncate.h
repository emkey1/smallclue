#ifndef SMALLCLUE_PATH_TRUNCATE_H
#define SMALLCLUE_PATH_TRUNCATE_H

#include <stdbool.h>
#include <stddef.h>

/* Platform shim: optionally expand a virtualized path into a real path. */
bool pathTruncateExpand(const char *path, char *buffer, size_t buflen);

/* Check if path truncation (virtual home) is enabled. */
bool pathTruncateEnabled(void);

/* Strip the virtual home prefix if present. */
bool pathTruncateStrip(const char *path, char *buffer, size_t buflen);

#endif /* SMALLCLUE_PATH_TRUNCATE_H */
