#ifndef SMALLCLUE_DATE_APP_H
#define SMALLCLUE_DATE_APP_H

#include <stdbool.h>
#include <time.h>

int smallclueDateCommand(int argc, char **argv);
/* GNU parse-datetime (as date -d and touch -d take it) relative to `now`. */
bool smallclueParseDatetime(const char *s, struct timespec now, struct timespec *out);

#endif /* SMALLCLUE_DATE_APP_H */
