/*
 * nohup: entirely absent before this. A standard process-control idiom
 * for backgrounding builds/services so they survive the controlling
 * terminal hanging up.
 */

#include "nohup_app.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int smallclueNohupCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "nohup: missing operand\n");
        return 127;
    }

    signal(SIGHUP, SIG_IGN);

    bool redirectedOutput = false;
    if (isatty(STDOUT_FILENO)) {
        char homePath[PATH_MAX];
        const char *candidates[2] = {"nohup.out", NULL};
        const char *home = getenv("HOME");
        if (home && *home) {
            snprintf(homePath, sizeof(homePath), "%s/nohup.out", home);
            candidates[1] = homePath;
        }
        FILE *outFile = NULL;
        const char *usedPath = NULL;
        for (int i = 0; i < 2 && !outFile; ++i) {
            if (!candidates[i]) continue;
            outFile = fopen(candidates[i], "a");
            if (outFile) usedPath = candidates[i];
        }
        if (!outFile) {
            fprintf(stderr, "nohup: failed to open a file for output: %s\n", strerror(errno));
            return 127;
        }
        int fd = fileno(outFile);
        bool stderrWasTty = isatty(STDERR_FILENO);
        dup2(fd, STDOUT_FILENO);
        /* Announce the redirection on the ORIGINAL stderr (still the real
         * terminal at this point) before possibly redirecting stderr too
         * -- otherwise this diagnostic would silently end up inside
         * nohup.out instead of being seen live by the user. */
        fprintf(stderr, "nohup: ignoring input and appending output to '%s'\n", usedPath);
        if (stderrWasTty) {
            dup2(fd, STDERR_FILENO);
        }
        fclose(outFile); /* underlying fd stays open via the dup2'd copies */
        redirectedOutput = true;
    }
    if (!redirectedOutput && isatty(STDERR_FILENO)) {
        /* stdout wasn't a terminal (already piped/redirected elsewhere) --
         * send stderr to wherever stdout is already going, matching GNU
         * nohup's behavior instead of always writing to nohup.out. */
        dup2(STDOUT_FILENO, STDERR_FILENO);
    }

    execvp(argv[1], &argv[1]);
    int err = errno;
    fprintf(stderr, "nohup: %s: %s\n", argv[1], strerror(err));
    return (err == ENOENT) ? 127 : 126;
}
