/*
 * nl: entirely absent before this. Line-numbering utility used in code
 * review/diff workflows and simple script pipelines.
 *
 * Scope note: supports the commonly-used -b/-w/-s options with GNU's
 * default numbering format (right-justified, no zero-fill). GNU nl's
 * further -n (format selector), -i/-v (increment/start value), and
 * page-break/header-footer section handling (-p, and the \1\1/\2\2/\3\3
 * section-delimiter convention) are not implemented -- real-world usage
 * is overwhelmingly the plain `nl file` / `nl -ba` / `nl -w N -s SEP`
 * forms this covers, verified against real GNU nl including its exact
 * blank-line spacing (unnumbered lines print width+separator-length
 * spaces, not a literal number field).
 */

#include "nl_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int smallclueNlCommand(int argc, char **argv) {
    bool numberAll = false; /* -b a: number every line, including blank ones */
    int width = 6;
    const char *sep = "\t";
    const char *path = NULL;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "-b") == 0 || (strncmp(arg, "-b", 2) == 0 && arg[2] != '\0')) {
            const char *style;
            if (strcmp(arg, "-b") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "nl: option requires an argument -- 'b'\n");
                    return 1;
                }
                style = argv[++i];
            } else {
                style = arg + 2;
            }
            if (strcmp(style, "a") == 0) numberAll = true;
            else if (strcmp(style, "t") == 0) numberAll = false;
            else {
                fprintf(stderr, "nl: unsupported -b style '%s' (only a/t)\n", style);
                return 1;
            }
        } else if (strcmp(arg, "-w") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "nl: option requires an argument -- 'w'\n");
                return 1;
            }
            width = atoi(argv[++i]);
        } else if (strncmp(arg, "-w", 2) == 0 && arg[2] != '\0') {
            width = atoi(arg + 2);
        } else if (strcmp(arg, "-s") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "nl: option requires an argument -- 's'\n");
                return 1;
            }
            sep = argv[++i];
        } else if (strncmp(arg, "-s", 2) == 0 && arg[2] != '\0') {
            sep = arg + 2;
        } else if (strcmp(arg, "--") == 0) {
            if (i + 1 < argc) path = argv[i + 1];
            break;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "nl: unsupported option '%s'\n", arg);
            return 1;
        } else {
            path = arg;
        }
    }

    FILE *in = stdin;
    bool needClose = false;
    if (path && strcmp(path, "-") != 0) {
        in = fopen(path, "r");
        if (!in) {
            fprintf(stderr, "nl: %s: %s\n", path, strerror(errno));
            return 1;
        }
        needClose = true;
    }

    long lineNo = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t sepLen = strlen(sep);
    while ((len = getline(&line, &cap, in)) != -1) {
        bool hadNewline = (len > 0 && line[len - 1] == '\n');
        if (hadNewline) line[len - 1] = '\0';
        bool isBlank = (line[0] == '\0');
        if (numberAll || !isBlank) {
            lineNo++;
            printf("%*ld%s%s", width, lineNo, sep, line);
        } else {
            printf("%*s%s", (int)(width + sepLen), "", line);
        }
        if (hadNewline) putchar('\n');
    }
    free(line);

    if (needClose) fclose(in);
    return 0;
}
