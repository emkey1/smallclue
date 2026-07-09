/*
 * awk: entirely absent before this. Targets the BusyBox awk feature
 * surface (POSIX awk core: patterns/actions, BEGIN/END, user functions,
 * arrays, getline, printf, string/math built-ins) rather than gawk's
 * extensions (no asort/gensub/strftime/bitwise functions/switch/etc).
 *
 * CLI matches BusyBox awk: -F SEP, -v VAR=VAL (repeatable), -f FILE
 * (repeatable; program text is the concatenation of all -f files, in
 * order, joined by newlines), -e PROGRAM (inline program text, an
 * alternative to the positional program argument). If no -f/-e is
 * given, the first non-option argument is the program text.
 */

#include "awk_app.h"
#include "awk_parser.h"
#include "awk_interp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *awkReadWholeFile(const char *path) {
    FILE *fp = strcmp(path, "-") == 0 ? stdin : fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "awk: %s: %s\n", path, strerror(errno));
        return NULL;
    }
    char *buf = NULL;
    size_t cap = 0, len = 0;
    char chunk[8192];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (len + n + 1 > cap) {
            while (len + n + 1 > cap) cap = cap ? cap * 2 : 16384;
            buf = (char *)realloc(buf, cap);
        }
        memcpy(buf + len, chunk, n);
        len += n;
        buf[len] = '\0';
    }
    if (fp != stdin) fclose(fp);
    if (!buf) buf = strdup("");
    return buf;
}

int smallclueAwkCommand(int argc, char **argv) {
    const char *fsOverride = NULL;
    char **assigns = NULL;
    int assignCount = 0;
    char *progText = NULL;
    bool haveProgSource = false;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) { argi++; break; }
        if (arg[0] != '-' || arg[1] == '\0') break;
        if (strcmp(arg, "-F") == 0) {
            if (argi + 1 >= argc) { fprintf(stderr, "awk: -F requires an argument\n"); return 2; }
            fsOverride = argv[++argi];
        } else if (strncmp(arg, "-F", 2) == 0) {
            fsOverride = arg + 2;
        } else if (strcmp(arg, "-v") == 0) {
            if (argi + 1 >= argc) { fprintf(stderr, "awk: -v requires an argument\n"); return 2; }
            assigns = (char **)realloc(assigns, sizeof(char *) * (size_t)(assignCount + 1));
            assigns[assignCount++] = argv[++argi];
        } else if (strncmp(arg, "-v", 2) == 0 && arg[2] != '\0') {
            assigns = (char **)realloc(assigns, sizeof(char *) * (size_t)(assignCount + 1));
            assigns[assignCount++] = (char *)(arg + 2);
        } else if (strcmp(arg, "-f") == 0 || strcmp(arg, "-E") == 0) {
            if (argi + 1 >= argc) { fprintf(stderr, "awk: -f requires an argument\n"); return 2; }
            char *content = awkReadWholeFile(argv[++argi]);
            if (!content) return 2;
            if (progText) {
                size_t oldLen = strlen(progText);
                size_t addLen = strlen(content);
                progText = (char *)realloc(progText, oldLen + addLen + 2);
                progText[oldLen] = '\n';
                memcpy(progText + oldLen + 1, content, addLen + 1);
                free(content);
            } else {
                progText = content;
            }
            haveProgSource = true;
        } else if (strncmp(arg, "-f", 2) == 0 && arg[2] != '\0') {
            char *content = awkReadWholeFile(arg + 2);
            if (!content) return 2;
            progText = content;
            haveProgSource = true;
        } else if (strcmp(arg, "-e") == 0) {
            if (argi + 1 >= argc) { fprintf(stderr, "awk: -e requires an argument\n"); return 2; }
            const char *piece = argv[++argi];
            if (progText) {
                size_t oldLen = strlen(progText);
                size_t addLen = strlen(piece);
                progText = (char *)realloc(progText, oldLen + addLen + 2);
                progText[oldLen] = '\n';
                memcpy(progText + oldLen + 1, piece, addLen + 1);
            } else {
                progText = strdup(piece);
            }
            haveProgSource = true;
        } else {
            fprintf(stderr, "awk: unsupported option '%s'\n", arg);
            return 2;
        }
    }

    if (!haveProgSource) {
        if (argi >= argc) {
            fprintf(stderr, "usage: awk [-F sep] [-v var=val] [-f progfile | -e prog | 'prog'] [file ...]\n");
            return 2;
        }
        progText = strdup(argv[argi++]);
    }

    AwkProgram *prog = awkParseProgram(progText);
    free(progText);
    if (!prog) {
        return 2;
    }

    int rc = awkRunProgram(prog, argc, argv, argi, assigns, assignCount, fsOverride);
    free(assigns);
    return rc;
}
