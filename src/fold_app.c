/*
 * fold: GNU coreutils 9 compatible -- GNU's fold_file: columns by byte,
 * with backspace, carriage return and tab stops (8) unless -b counts every
 * byte as one; -s breaks after the last blank and rescans the rest; the
 * obsolete -NUM width; GNU's messages.
 */

#include "fold_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t foldColumn(size_t col, int c, bool bytes) {
    if (bytes) return col + 1;
    if (c == '\b') return col > 0 ? col - 1 : 0;
    if (c == '\r') return 0;
    if (c == '\t') return col + 8 - col % 8;
    return col + 1;
}

static bool foldFile(FILE *in, size_t width, bool bytes, bool spaces) {
    size_t cap = 256, off = 0, col = 0;
    char *line = (char *)malloc(cap);
    if (!line) return false;
    int c;
    while ((c = getc(in)) != EOF) {
        if (off + 2 >= cap) {
            cap *= 2;
            char *p = (char *)realloc(line, cap);
            if (!p) break;
            line = p;
        }
        if (c == '\n') {
            line[off++] = (char)c;
            fwrite(line, 1, off, stdout);
            col = off = 0;
            continue;
        }
    rescan:
        col = foldColumn(col, c, bytes);
        if (col > width) {
            if (spaces) {
                size_t end = off;
                bool blank = false;
                while (end) {
                    --end;
                    if (line[end] == ' ' || line[end] == '\t') {
                        blank = true;
                        break;
                    }
                }
                if (blank) {
                    end++;
                    fwrite(line, 1, end, stdout);
                    putchar('\n');
                    memmove(line, line + end, off - end);
                    off -= end;
                    col = 0;
                    for (size_t i = 0; i < off; i++) col = foldColumn(col, (unsigned char)line[i], bytes);
                    goto rescan;
                }
            }
            if (off == 0) {
                line[off++] = (char)c;
                continue;
            }
            line[off++] = '\n';
            fwrite(line, 1, off, stdout);
            col = off = 0;
            goto rescan;
        }
        line[off++] = (char)c;
    }
    if (off) fwrite(line, 1, off, stdout);
    free(line);
    return true;
}

static const GnuLongOpt foldLongs[] = {
    {"bytes", GNU_NO_ARG, 'b'}, {"spaces", GNU_NO_ARG, 's'}, {"width", GNU_REQ_ARG, 'w'},
    {"help", GNU_NO_ARG, 1},    {"version", GNU_NO_ARG, 2},
};

int smallclueFoldCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "fold", "bsw:0::1::2::3::4::5::6::7::8::9::", foldLongs,
                  sizeof(foldLongs) / sizeof(foldLongs[0]));
    bool bytes = false, spaces = false;
    size_t width = 80;
    int c, status = 0;
    char q[512], digits[64];
    while ((c = gnuGetopt(&g)) != -1) {
        const char *w = NULL;
        switch (c) {
        case 'b': bytes = true; break;
        case 's': spaces = true; break;
        case 'w': w = g.arg; break;
        case 1:
            fputs("Usage: fold [OPTION]... [FILE]...\n"
                  "Wrap input lines in each FILE, writing to standard output.\n\n"
                  "With no FILE, or when FILE is -, read standard input.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -b, --bytes         count bytes rather than columns\n"
                  "  -s, --spaces        break at spaces\n"
                  "  -w, --width=WIDTH   use WIDTH columns instead of 80\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            goto done;
        case 2: puts("fold (SmallCLUE) 9.4"); goto done;
        default:
            if (c >= '0' && c <= '9') {
                snprintf(digits, sizeof(digits), "%c%s", c, g.arg ? g.arg : "");
                w = digits;
                break;
            }
            fputs("Try 'fold --help' for more information.\n", stderr);
            status = 1;
            goto done;
        }
        if (w) {
            char *end;
            errno = 0;
            intmax_t v = strtoimax(w, &end, 10);
            if (end == w || *end) {
                fprintf(stderr, "fold: invalid number of columns: %s\n", gnuQuoteLocale(w, q, sizeof(q)));
                status = 1;
                goto done;
            }
            if (errno == ERANGE || v < 1 || (uintmax_t)v > SIZE_MAX - 9) {
                /* xdectoumax: out of range, overflow included, is ERANGE */
                fprintf(stderr, "fold: invalid number of columns: %s: Numerical result out of range\n",
                        gnuQuoteLocale(w, q, sizeof(q)));
                status = 1;
                goto done;
            }
            width = (size_t)v;
        }
    }
    for (int i = 0; i < (g.nops ? g.nops : 1); i++) {
        const char *name = g.nops ? g.ops[i] : "-";
        bool isStdin = !strcmp(name, "-");
        FILE *f = isStdin ? stdin : smallclueAppOpenRead(name);
        if (!f) {
            fprintf(stderr, "fold: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            status = 1;
            continue;
        }
        foldFile(f, width, bytes, spaces);
        if (ferror(f)) {
            fprintf(stderr, "fold: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            status = 1;
        }
        if (isStdin) clearerr(stdin);
        else fclose(f);
    }
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("fold", errno);
        status = 1;
    }
    return status;
}
