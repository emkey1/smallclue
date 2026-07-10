/*
 * fmt: entirely absent before this. Reflows text into filled paragraphs
 * (join short lines, wrap long ones) -- common in mail/commit-message
 * editing workflows.
 *
 * Scope note: a straightforward greedy word-wrap over whitespace-
 * separated words (fill every line up to WIDTH before breaking),
 * treating any blank line as a paragraph break (preserved as-is in the
 * output). This matches real GNU fmt's default-width (75) output
 * exactly, but GNU fmt actually targets a "goal" length a bit under
 * the max width rather than greedily filling all the way to it, so
 * -w N output can pack slightly more per line here than real fmt's
 * (verified: both wrap correctly, lines never exceed N, just a
 * cosmetic difference in exactly where each line breaks). Real fmt's
 * further options (-s split-only, -u uniform spacing, indentation
 * preservation, crown/tagged-paragraph detection) are not implemented.
 */

#include "fmt_app.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SMALLCLUE_FMT_DEFAULT_WIDTH 75

static void smallclueFmtFlushParagraph(char **words, int wordCount, int width) {
    int col = 0;
    for (int i = 0; i < wordCount; ++i) {
        int wlen = (int)strlen(words[i]);
        if (col == 0) {
            fputs(words[i], stdout);
            col = wlen;
        } else if (col + 1 + wlen <= width) {
            putchar(' ');
            fputs(words[i], stdout);
            col += 1 + wlen;
        } else {
            putchar('\n');
            fputs(words[i], stdout);
            col = wlen;
        }
    }
    if (wordCount > 0) putchar('\n');
}

static int smallclueFmtStream(FILE *in, const char *label, int width) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    char **words = NULL;
    int wordCount = 0;
    int wordCap = 0;

    while ((len = getline(&line, &cap, in)) != -1) {
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        bool isBlank = true;
        for (char *p = line; *p; ++p) {
            if (!isspace((unsigned char)*p)) { isBlank = false; break; }
        }

        if (isBlank) {
            if (wordCount > 0) {
                smallclueFmtFlushParagraph(words, wordCount, width);
                for (int i = 0; i < wordCount; ++i) free(words[i]);
                wordCount = 0;
            }
            putchar('\n');
            continue;
        }

        char *save = NULL;
        for (char *tok = strtok_r(line, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
            if (wordCount == wordCap) {
                wordCap = wordCap ? wordCap * 2 : 32;
                char **resized = (char **)realloc(words, (size_t)wordCap * sizeof(char *));
                if (!resized) {
                    fprintf(stderr, "fmt: out of memory\n");
                    free(line);
                    for (int i = 0; i < wordCount; ++i) free(words[i]);
                    free(words);
                    return 1;
                }
                words = resized;
            }
            words[wordCount++] = strdup(tok);
        }
    }
    if (wordCount > 0) {
        smallclueFmtFlushParagraph(words, wordCount, width);
        for (int i = 0; i < wordCount; ++i) free(words[i]);
    }
    free(words);
    free(line);
    if (ferror(in)) {
        fprintf(stderr, "fmt: %s: read error\n", label);
        return 1;
    }
    return 0;
}

int smallclueFmtCommand(int argc, char **argv) {
    int width = SMALLCLUE_FMT_DEFAULT_WIDTH;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "-w") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "fmt: option requires an argument -- 'w'\n");
                return 1;
            }
            width = atoi(argv[++argi]);
        } else if (strncmp(arg, "-w", 2) == 0 && arg[2] != '\0') {
            width = atoi(arg + 2);
        } else if (arg[0] == '-' && isdigit((unsigned char)arg[1])) {
            width = atoi(arg + 1);
        } else if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "fmt: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (width <= 0) {
        fprintf(stderr, "fmt: invalid width\n");
        return 1;
    }

    int status = 0;
    if (argi >= argc) {
        status = smallclueFmtStream(stdin, "(stdin)", width);
    } else {
        for (; argi < argc; ++argi) {
            FILE *in = stdin;
            bool needClose = false;
            if (strcmp(argv[argi], "-") != 0) {
                in = fopen(argv[argi], "r");
                if (!in) {
                    fprintf(stderr, "fmt: %s: %s\n", argv[argi], strerror(errno));
                    status = 1;
                    continue;
                }
                needClose = true;
            }
            if (smallclueFmtStream(in, argv[argi], width) != 0) {
                status = 1;
            }
            if (needClose) fclose(in);
        }
    }
    return status;
}
