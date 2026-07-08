/*
 * tac: entirely absent before this. Prints lines in reverse order --
 * "cat backwards", useful for reading recent log entries first.
 *
 * Real tac keeps each line's trailing separator attached to the END of
 * that line's own record rather than treating the separator as a
 * standalone token, which produces a specific (verified against real
 * GNU tac) result for input with no final trailing newline: the last
 * "line" (no newline) ends up glued onto the front of the line that
 * becomes first after reversal, with no newline between them. This
 * implementation reproduces that exactly by reading the whole file into
 * memory and reversing record boundaries the same way (newline stays
 * attached to the preceding text).
 */

#include "tac_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int smallclueTacPrintReversed(FILE *in, const char *label) {
    char *data = NULL;
    size_t len = 0;
    size_t cap = 0;
    char buf[16384];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (len + n > cap) {
            size_t newCap = cap ? cap * 2 : 16384;
            while (newCap < len + n) newCap *= 2;
            char *resized = (char *)realloc(data, newCap);
            if (!resized) {
                fprintf(stderr, "tac: out of memory\n");
                free(data);
                return 1;
            }
            data = resized;
            cap = newCap;
        }
        memcpy(data + len, buf, n);
        len += n;
    }
    if (ferror(in)) {
        fprintf(stderr, "tac: %s: read error\n", label);
        free(data);
        return 1;
    }

    /* Record boundaries: position 0, then every index right after a '\n',
     * then len itself (covering a final partial record with no trailing
     * newline). Building this list explicitly avoids an off-by-one when
     * deciding whether a record's own trailing newline is included. */
    size_t *bounds = (size_t *)malloc(sizeof(size_t) * (len + 2));
    if (!bounds) {
        fprintf(stderr, "tac: out of memory\n");
        free(data);
        return 1;
    }
    size_t boundCount = 0;
    bounds[boundCount++] = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == '\n') {
            bounds[boundCount++] = i + 1;
        }
    }
    if (boundCount == 0 || bounds[boundCount - 1] != len) {
        bounds[boundCount++] = len;
    }

    for (size_t b = boundCount - 1; b > 0; --b) {
        size_t start = bounds[b - 1];
        size_t recEnd = bounds[b];
        fwrite(data + start, 1, recEnd - start, stdout);
    }
    free(bounds);
    free(data);
    return 0;
}

int smallclueTacCommand(int argc, char **argv) {
    int status = 0;
    if (argc <= 1) {
        status = smallclueTacPrintReversed(stdin, "(stdin)");
    } else {
        for (int i = 1; i < argc; ++i) {
            FILE *in = stdin;
            bool needClose = false;
            if (strcmp(argv[i], "-") != 0) {
                in = fopen(argv[i], "rb");
                if (!in) {
                    fprintf(stderr, "tac: %s: %s\n", argv[i], strerror(errno));
                    status = 1;
                    continue;
                }
                needClose = true;
            }
            if (smallclueTacPrintReversed(in, argv[i]) != 0) {
                status = 1;
            }
            if (needClose) fclose(in);
        }
    }
    return status;
}
