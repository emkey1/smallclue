/*
 * paste: entirely absent before this. Merges corresponding lines of
 * multiple files side by side (the classic use: recombining columns
 * that were split out with `cut`).
 */

#include "paste_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char smallcluePasteDelimAt(const char *delims, size_t delimCount, size_t index) {
    if (delimCount == 0) return '\t';
    return delims[index % delimCount];
}

int smallcluePasteCommand(int argc, char **argv) {
    bool serial = false;
    const char *delims = "\t";
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "-s") == 0) {
            serial = true;
        } else if (strcmp(arg, "-d") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "paste: option requires an argument -- 'd'\n");
                return 1;
            }
            delims = argv[++argi];
        } else if (strncmp(arg, "-d", 2) == 0 && arg[2] != '\0') {
            delims = arg + 2;
        } else if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "paste: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    size_t delimCount = strlen(delims);

    int fileCount = argc - argi;
    if (fileCount <= 0) {
        argv = (char *[]){ NULL, (char *)"-" };
        argi = 1;
        fileCount = 1;
        argc = 2;
    }

    FILE **files = (FILE **)calloc((size_t)fileCount, sizeof(FILE *));
    if (!files) {
        fprintf(stderr, "paste: out of memory\n");
        return 1;
    }
    int status = 0;
    for (int i = 0; i < fileCount; ++i) {
        const char *path = argv[argi + i];
        if (strcmp(path, "-") == 0) {
            files[i] = stdin;
        } else {
            files[i] = fopen(path, "r");
            if (!files[i]) {
                fprintf(stderr, "paste: %s: %s\n", path, strerror(errno));
                status = 1;
            }
        }
    }

    if (serial) {
        for (int i = 0; i < fileCount; ++i) {
            if (!files[i]) continue;
            char *line = NULL;
            size_t cap = 0;
            ssize_t len;
            bool first = true;
            size_t col = 0;
            while ((len = getline(&line, &cap, files[i])) != -1) {
                if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
                if (!first) putchar(smallcluePasteDelimAt(delims, delimCount, col++));
                fputs(line, stdout);
                first = false;
            }
            free(line);
            if (!first) putchar('\n');
        }
    } else {
        char **lines = (char **)calloc((size_t)fileCount, sizeof(char *));
        size_t *caps = (size_t *)calloc((size_t)fileCount, sizeof(size_t));
        bool *atEof = (bool *)calloc((size_t)fileCount, sizeof(bool));
        if (!lines || !caps || !atEof) {
            fprintf(stderr, "paste: out of memory\n");
            free(lines); free(caps); free(atEof);
            for (int i = 0; i < fileCount; ++i) if (files[i] && files[i] != stdin) fclose(files[i]);
            free(files);
            return 1;
        }
        for (int i = 0; i < fileCount; ++i) {
            if (!files[i]) atEof[i] = true;
        }
        for (;;) {
            bool anyLine = false;
            ssize_t got[fileCount ? fileCount : 1];
            for (int i = 0; i < fileCount; ++i) {
                if (atEof[i]) { got[i] = -1; continue; }
                got[i] = getline(&lines[i], &caps[i], files[i]);
                if (got[i] == -1) {
                    atEof[i] = true;
                } else {
                    anyLine = true;
                    if (got[i] > 0 && lines[i][got[i] - 1] == '\n') {
                        lines[i][got[i] - 1] = '\0';
                    }
                }
            }
            if (!anyLine) break;
            for (int i = 0; i < fileCount; ++i) {
                if (i > 0) putchar(smallcluePasteDelimAt(delims, delimCount, (size_t)i - 1));
                if (got[i] != -1) fputs(lines[i], stdout);
            }
            putchar('\n');
        }
        for (int i = 0; i < fileCount; ++i) free(lines[i]);
        free(lines);
        free(caps);
        free(atEof);
    }

    for (int i = 0; i < fileCount; ++i) {
        if (files[i] && files[i] != stdin) fclose(files[i]);
    }
    free(files);
    return status;
}
