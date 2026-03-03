#include "dvtm_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SMALLCLUE_WITH_DVTM)
extern int dvtm_main_entry(int argc, char **argv);

int smallclueRunDvtm(int argc, char **argv) {
    const char *saved_term = getenv("TERM");
    char *saved_term_copy = NULL;
    if (saved_term && saved_term[0] != '\0') {
        saved_term_copy = strdup(saved_term);
    } else {
        setenv("TERM", "xterm-256color", 1);
    }
    if (!getenv("DVTM_TERM")) {
        setenv("DVTM_TERM", "xterm-256color", 1);
    }

    int status = dvtm_main_entry(argc, argv);

    if (saved_term_copy) {
        setenv("TERM", saved_term_copy, 1);
    } else {
        unsetenv("TERM");
    }
    free(saved_term_copy);
    return status;
}
#else
int smallclueRunDvtm(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("dvtm: applet is disabled in this build (enable SMALLCLUE_WITH_DVTM)\n", stderr);
    return 127;
}
#endif
