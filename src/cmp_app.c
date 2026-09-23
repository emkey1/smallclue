/*
 * cmp: entirely absent before this (diff exists, but cmp is a distinct,
 * simpler byte-for-byte comparison tool -- useful for verifying build
 * outputs and downloaded artifacts without diff's line-oriented output).
 */

#include "cmp_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int smallclueCmpCompare(FILE *f1, const char *name1, FILE *f2, const char *name2,
                                bool silent, bool listAll) {
    long byteNum = 0;
    long lineNum = 1;
    bool anyDiff = false;
    unsigned char buf1[16384];
    unsigned char buf2[16384];
    size_t len1 = 0, len2 = 0;
    size_t i1 = 0, i2 = 0;
    for (;;) {
        if (i1 >= len1) {
            len1 = fread(buf1, 1, sizeof(buf1), f1);
            i1 = 0;
        }
        if (i2 >= len2) {
            len2 = fread(buf2, 1, sizeof(buf2), f2);
            i2 = 0;
        }
        bool eof1 = (len1 == 0);
        bool eof2 = (len2 == 0);
        if (eof1 || eof2) {
            if (eof1 && eof2) {
                return anyDiff ? 1 : 0;
            }
            if (!silent) {
                fprintf(stderr, "cmp: EOF on %s\n", eof1 ? name1 : name2);
            }
            return 1;
        }

        size_t avail1 = len1 - i1;
        size_t avail2 = len2 - i2;
        size_t n = avail1 < avail2 ? avail1 : avail2;

        for (size_t k = 0; k < n; ++k) {
            byteNum++;
            unsigned char c1 = buf1[i1++];
            unsigned char c2 = buf2[i2++];
            if (c1 != c2) {
                anyDiff = true;
                if (listAll) {
                    if (!silent) {
                        printf("%6ld %3o %3o\n", byteNum, c1, c2);
                    }
                } else {
                    if (!silent) {
                        printf("%s %s differ: char %ld, line %ld\n", name1, name2, byteNum, lineNum);
                    }
                    return 1;
                }
            }
            if (c1 == '\n') {
                lineNum++;
            }
        }
    }
}

int smallclueCmpCommand(int argc, char **argv) {
    bool silent = false;
    bool listAll = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-s") == 0 || strcmp(arg, "--quiet") == 0 || strcmp(arg, "--silent") == 0) {
            silent = true;
            continue;
        }
        if (strcmp(arg, "-l") == 0 || strcmp(arg, "--verbose") == 0) {
            listAll = true;
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "cmp: unsupported option '%s'\n", arg);
            return 2;
        }
        break;
    }

    if (argc - argi != 2) {
        fprintf(stderr, "usage: cmp [-s] [-l] file1 file2\n");
        return 2;
    }
    const char *name1 = argv[argi];
    const char *name2 = argv[argi + 1];

    bool stdin1 = strcmp(name1, "-") == 0;
    bool stdin2 = strcmp(name2, "-") == 0;
    if (stdin1 && stdin2) {
        fprintf(stderr, "cmp: only one file may be '-' (stdin)\n");
        return 2;
    }
    if (stdin1) name1 = "stdin";
    if (stdin2) name2 = "stdin";

    FILE *f1 = stdin1 ? stdin : fopen(name1, "rb");
    if (!f1) {
        fprintf(stderr, "cmp: %s: %s\n", name1, strerror(errno));
        return 2;
    }
    FILE *f2 = stdin2 ? stdin : fopen(name2, "rb");
    if (!f2) {
        if (!stdin1) fclose(f1);
        fprintf(stderr, "cmp: %s: %s\n", name2, strerror(errno));
        return 2;
    }

    int status = smallclueCmpCompare(f1, name1, f2, name2, silent, listAll);

    if (!stdin1) fclose(f1);
    if (!stdin2) fclose(f2);
    return status;
}
