#ifndef SMALLCLUE_MICRO_APP_H
#define SMALLCLUE_MICRO_APP_H

#include <stdint.h>

int smallclueRunMicro(int argc, char **argv);
void pscalMicroNotifySessionWinsize(uint64_t session_id, int cols, int rows);

#endif /* SMALLCLUE_MICRO_APP_H */
