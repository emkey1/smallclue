/*
 * comm: entirely absent before this. Compares two SORTED files line by
 * line via a merge (not a full read-and-hash), printing up to 3 columns:
 * lines only in file1, lines only in file2, lines in both.
 *
 * Assumes both inputs are already sorted (matching real comm, which does
 * not sort for you and produces meaningless output on unsorted input).
 */

#include "comm_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool smallclueCommNextLine(FILE *fp, char **line, size_t *cap, bool *atEof) {
    if (*atEof) return false;
    ssize_t n = getline(line, cap, fp);
    if (n == -1) {
        *atEof = true;
        return false;
    }
    if (n > 0 && (*line)[n - 1] == '\n') (*line)[n - 1] = '\0';
    return true;
}

int smallclueCommCommand(int argc, char **argv) {
    bool suppress1 = false, suppress2 = false, suppress3 = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (arg[0] != '-' || arg[1] == '\0') break;
        if (strcmp(arg, "--") == 0) { argi++; break; }
        bool recognized = true;
        for (const char *p = arg + 1; *p; ++p) {
            if (*p == '1') suppress1 = true;
            else if (*p == '2') suppress2 = true;
            else if (*p == '3') suppress3 = true;
            else { recognized = false; break; }
        }
        if (!recognized) {
            fprintf(stderr, "comm: unsupported option '%s'\n", arg);
            return 1;
        }
    }
    if (argc - argi != 2) {
        fprintf(stderr, "usage: comm [-1] [-2] [-3] FILE1 FILE2\n");
        return 1;
    }

    const char *path1 = argv[argi];
    const char *path2 = argv[argi + 1];
    FILE *f1 = strcmp(path1, "-") == 0 ? stdin : fopen(path1, "r");
    if (!f1) {
        fprintf(stderr, "comm: %s: %s\n", path1, strerror(errno));
        return 1;
    }
    FILE *f2 = strcmp(path2, "-") == 0 ? stdin : fopen(path2, "r");
    if (!f2) {
        fprintf(stderr, "comm: %s: %s\n", path2, strerror(errno));
        if (f1 != stdin) fclose(f1);
        return 1;
    }

    const char *prefix2 = suppress1 ? "" : "\t";
    int prefix3Tabs = (suppress1 ? 0 : 1) + (suppress2 ? 0 : 1);

    char *line1 = NULL, *line2 = NULL;
    size_t cap1 = 0, cap2 = 0;
    bool eof1 = false, eof2 = false;
    bool have1 = smallclueCommNextLine(f1, &line1, &cap1, &eof1);
    bool have2 = smallclueCommNextLine(f2, &line2, &cap2, &eof2);

    while (have1 || have2) {
        int cmp;
        if (have1 && have2) cmp = strcmp(line1, line2);
        else if (have1) cmp = -1;
        else cmp = 1;

        if (cmp < 0) {
            if (!suppress1) printf("%s\n", line1);
            have1 = smallclueCommNextLine(f1, &line1, &cap1, &eof1);
        } else if (cmp > 0) {
            if (!suppress2) printf("%s%s\n", prefix2, line2);
            have2 = smallclueCommNextLine(f2, &line2, &cap2, &eof2);
        } else {
            if (!suppress3) {
                for (int i = 0; i < prefix3Tabs; ++i) putchar('\t');
                printf("%s\n", line1);
            }
            have1 = smallclueCommNextLine(f1, &line1, &cap1, &eof1);
            have2 = smallclueCommNextLine(f2, &line2, &cap2, &eof2);
        }
    }

    free(line1);
    free(line2);
    if (f1 != stdin) fclose(f1);
    if (f2 != stdin) fclose(f2);
    return 0;
}
