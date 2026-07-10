/*
 * fold: entirely absent before this. Wraps long lines to a fixed width --
 * useful for viewing wide output (log lines, generated code) in a
 * narrow terminal or piping into something that assumes bounded width.
 *
 * Scope note: width is a plain character count (no tab-expansion-to-8-
 * column-stops or wide-character/locale awareness); verified against
 * real GNU fold for plain ASCII input, which is the overwhelming common
 * case for this utility.
 */

#include "fold_app.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void smallclueFoldWrapLine(const char *line, size_t len, int width, bool spaceBreak, bool hadNewline) {
    size_t pos = 0;
    while (pos < len) {
        size_t remaining = len - pos;
        if (remaining <= (size_t)width) {
            fwrite(line + pos, 1, remaining, stdout);
            if (hadNewline) putchar('\n');
            pos = len;
            break;
        }
        size_t chunkEnd = pos + (size_t)width;
        size_t breakAt = chunkEnd; /* exclusive end of what we print this line */
        if (spaceBreak) {
            size_t lastSpace = (size_t)-1;
            for (size_t i = pos; i < chunkEnd; ++i) {
                if (isspace((unsigned char)line[i])) lastSpace = i;
            }
            if (lastSpace != (size_t)-1) {
                breakAt = lastSpace + 1;
            }
        }
        fwrite(line + pos, 1, breakAt - pos, stdout);
        putchar('\n');
        pos = breakAt;
    }
    if (len == 0 && hadNewline) {
        putchar('\n');
    }
}

static int smallclueFoldStream(FILE *in, const char *label, int width, bool spaceBreak) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) != -1) {
        bool hadNewline = (n > 0 && line[n - 1] == '\n');
        size_t contentLen = hadNewline ? (size_t)(n - 1) : (size_t)n;
        smallclueFoldWrapLine(line, contentLen, width, spaceBreak, hadNewline);
    }
    free(line);
    if (ferror(in)) {
        fprintf(stderr, "fold: %s: read error\n", label);
        return 1;
    }
    return 0;
}

int smallclueFoldCommand(int argc, char **argv) {
    int width = 80;
    bool spaceBreak = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "-s") == 0) {
            spaceBreak = true;
        } else if (strcmp(arg, "-w") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "fold: option requires an argument -- 'w'\n");
                return 1;
            }
            width = atoi(argv[++argi]);
        } else if (strncmp(arg, "-w", 2) == 0 && arg[2] != '\0') {
            width = atoi(arg + 2);
        } else if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        } else if (arg[0] == '-' && arg[1] != '\0' && !isdigit((unsigned char)arg[1])) {
            fprintf(stderr, "fold: unsupported option '%s'\n", arg);
            return 1;
        } else if (arg[0] == '-' && isdigit((unsigned char)arg[1])) {
            width = atoi(arg + 1);
        } else {
            break;
        }
    }
    if (width <= 0) {
        fprintf(stderr, "fold: invalid width\n");
        return 1;
    }

    int status = 0;
    if (argi >= argc) {
        status = smallclueFoldStream(stdin, "(stdin)", width, spaceBreak);
    } else {
        for (; argi < argc; ++argi) {
            FILE *in = stdin;
            bool needClose = false;
            if (strcmp(argv[argi], "-") != 0) {
                in = fopen(argv[argi], "r");
                if (!in) {
                    fprintf(stderr, "fold: %s: %s\n", argv[argi], strerror(errno));
                    status = 1;
                    continue;
                }
                needClose = true;
            }
            if (smallclueFoldStream(in, argv[argi], width, spaceBreak) != 0) {
                status = 1;
            }
            if (needClose) fclose(in);
        }
    }
    return status;
}
