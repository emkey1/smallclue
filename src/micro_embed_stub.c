#include <stdio.h>
#include <stdint.h>

int pscal_micro_go_main_entry(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("micro embed is unavailable in this host test build.\n", stderr);
    return 127;
}

int pscal_micro_go_notify_resize(uint64_t session_id, int cols, int rows) {
    (void)session_id;
    (void)cols;
    (void)rows;
    return 0;
}
