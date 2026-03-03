#if !defined(PSCAL_TARGET_IOS)
#include <stdio.h>

int pscal_micro_main_entry(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("micro embed is unavailable in this build.\n", stderr);
    return 127;
}
#endif
