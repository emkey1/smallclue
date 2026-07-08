/*
 * rev: entirely absent before this. Reverses the characters of each
 * line -- small but genuinely useful for column-oriented text tricks
 * (e.g. `rev | cut -c1 | rev` to grab a trailing field).
 */

#include "rev_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int smallclueRevStream(FILE *in, const char *label) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, in)) != -1) {
        bool hadNewline = (len > 0 && line[len - 1] == '\n');
        ssize_t contentLen = hadNewline ? len - 1 : len;
        for (ssize_t i = contentLen - 1; i >= 0; --i) {
            putchar((unsigned char)line[i]);
        }
        if (hadNewline) putchar('\n');
    }
    free(line);
    if (ferror(in)) {
        fprintf(stderr, "rev: %s: read error\n", label);
        return 1;
    }
    return 0;
}

int smallclueRevCommand(int argc, char **argv) {
    int status = 0;
    if (argc <= 1) {
        status = smallclueRevStream(stdin, "(stdin)");
    } else {
        for (int i = 1; i < argc; ++i) {
            FILE *in = stdin;
            bool needClose = false;
            if (strcmp(argv[i], "-") != 0) {
                in = fopen(argv[i], "r");
                if (!in) {
                    fprintf(stderr, "rev: %s: %s\n", argv[i], strerror(errno));
                    status = 1;
                    continue;
                }
                needClose = true;
            }
            if (smallclueRevStream(in, argv[i]) != 0) {
                status = 1;
            }
            if (needClose) fclose(in);
        }
    }
    return status;
}
