#include <stdio.h>

int pscal_micro_go_main_entry(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("micro embed is unavailable in this host test build.\n", stderr);
    return 127;
}
