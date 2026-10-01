/*
 * cat: GNU coreutils 9 compatible. -b -n -s -v -E -T -A -e -t -u with
 * GNU's line state carried across files (numbering continues, a file that
 * ends mid-line runs into the next, -s squeezes across the boundary), no
 * "$" after a last line without a newline, ^M$ for CRLF under -E alone,
 * "Is a directory" and "input file is output file" as errors, and each
 * buffer written as it is read (cat in a pipeline does not hold output).
 */

#include "cat_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    bool number, nonblank, squeeze, nonprinting, ends, tabs;
    int newlines;          /* consecutive newlines; -1 mid-line (GNU's newlines2) */
    uintmax_t line;
} Cat;

static void catNumber(Cat *c) {
    printf("%6ju\t", ++c->line);
}

static void catChunk(Cat *c, const unsigned char *b, size_t n, int next) {
    for (size_t i = 0; i < n; i++) {
        int ch = b[i];
        if (ch == '\n') {
            if (++c->newlines > 0) {
                if (c->newlines >= 2) {
                    c->newlines = 2;
                    if (c->squeeze) continue;
                }
                if (c->number && !c->nonblank) catNumber(c);
            }
            if (c->ends) putchar('$');
            putchar('\n');
            continue;
        }
        if (c->newlines >= 0 && c->number) catNumber(c);
        c->newlines = -1;
        if (c->nonprinting) {
            if (ch >= 32) {
                if (ch < 127) {
                    putchar(ch);
                } else if (ch == 127) {
                    fputs("^?", stdout);
                } else {
                    fputs("M-", stdout);
                    if (ch >= 128 + 32) {
                        if (ch < 128 + 127) putchar(ch - 128);
                        else fputs("^?", stdout);
                    } else {
                        putchar('^');
                        putchar(ch - 128 + 64);
                    }
                }
            } else if (ch == '\t' && !c->tabs) {
                putchar('\t');
            } else {
                putchar('^');
                putchar(ch + 64);
            }
        } else if (ch == '\t' && c->tabs) {
            fputs("^I", stdout);
        } else if (ch == '\r' && c->ends && (i + 1 < n ? b[i + 1] : next) == '\n') {
            fputs("^M", stdout);
        } else {
            putchar(ch);
        }
    }
}

/* false (after the message) on a failure. */
static bool catFile(Cat *c, const char *name, bool plain, const struct stat *out) {
    char q[4096];
    bool isStdin = !strcmp(name, "-");
    int fd = isStdin ? STDIN_FILENO : -1;
    FILE *f = NULL;
    if (!isStdin) {
        f = smallclueAppOpenRead(name);
        if (!f) {
            fprintf(stderr, "cat: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            return false;
        }
        fd = fileno(f);
    }
    struct stat st;
    if (out && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_dev == out->st_dev &&
        st.st_ino == out->st_ino && lseek(fd, 0, SEEK_CUR) < st.st_size) {
        fprintf(stderr, "cat: %s: input file is output file\n", gnuQuoteMaybe(name, q, sizeof(q)));
        if (f) fclose(f);
        return false;
    }
    unsigned char buf[65536];
    bool ok = true;
    int pending = -1;   /* a byte read ahead, for the CRLF look */
    for (;;) {
        ssize_t n;
        if (pending >= 0) {
            n = read(fd, buf + 1, sizeof(buf) - 1);
            if (n == 0) break;   /* EOF: the held CR is written below */
            if (n < 0 && errno == EINTR) continue;
            buf[0] = (unsigned char)pending;
            pending = -1;
            if (n > 0) n++;
        } else {
            n = read(fd, buf, sizeof(buf));
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "cat: %s: %s\n", gnuQuoteMaybe(name, q, sizeof(q)), strerror(errno));
            ok = false;
            break;
        }
        if (n == 0) break;
        if (plain) {
            fwrite(buf, 1, (size_t)n, stdout);
        } else if (c->ends && !c->nonprinting && buf[n - 1] == '\r') {
            /* hold a final CR until we know whether LF follows */
            pending = '\r';
            catChunk(c, buf, (size_t)n - 1, '\r');
        } else {
            catChunk(c, buf, (size_t)n, -1);
        }
        if (fflush(stdout) != 0) break;
    }
    if (pending >= 0) catChunk(c, (const unsigned char *)"\r", 1, -1);
    if (f) fclose(f);
    return ok;
}

static const GnuLongOpt catLongs[] = {
    {"number-nonblank", GNU_NO_ARG, 'b'}, {"number", GNU_NO_ARG, 'n'},
    {"squeeze-blank", GNU_NO_ARG, 's'},   {"show-nonprinting", GNU_NO_ARG, 'v'},
    {"show-ends", GNU_NO_ARG, 'E'},       {"show-tabs", GNU_NO_ARG, 'T'},
    {"show-all", GNU_NO_ARG, 'A'},        {"help", GNU_NO_ARG, 1},
    {"version", GNU_NO_ARG, 2},
};

int smallclueCatCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "cat", "benstuvAET", catLongs, sizeof(catLongs) / sizeof(catLongs[0]));
    Cat c;
    memset(&c, 0, sizeof(c));
    int ch, status = 0;
    while ((ch = gnuGetopt(&g)) != -1) {
        switch (ch) {
        case 'b': c.number = c.nonblank = true; break;
        case 'e': c.ends = c.nonprinting = true; break;
        case 'n': c.number = true; break;
        case 's': c.squeeze = true; break;
        case 't': c.tabs = c.nonprinting = true; break;
        case 'u': break;
        case 'v': c.nonprinting = true; break;
        case 'A': c.nonprinting = c.ends = c.tabs = true; break;
        case 'E': c.ends = true; break;
        case 'T': c.tabs = true; break;
        case 1:
            fputs("Usage: cat [OPTION]... [FILE]...\n"
                  "Concatenate FILE(s) to standard output.\n\n"
                  "With no FILE, or when FILE is -, read standard input.\n\n"
                  "  -A, --show-all           equivalent to -vET\n"
                  "  -b, --number-nonblank    number nonempty output lines, overrides -n\n"
                  "  -e                       equivalent to -vE\n"
                  "  -E, --show-ends          display $ at end of each line\n"
                  "  -n, --number             number all output lines\n"
                  "  -s, --squeeze-blank      suppress repeated empty output lines\n"
                  "  -t                       equivalent to -vT\n"
                  "  -T, --show-tabs          display TAB characters as ^I\n"
                  "  -u                       (ignored)\n"
                  "  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            goto done;
        case 2: puts("cat (SmallCLUE) 9.4"); goto done;
        default:
            fputs("Try 'cat --help' for more information.\n", stderr);
            status = 1;
            goto done;
        }
    }
    {
        bool plain = !(c.number || c.squeeze || c.nonprinting || c.ends || c.tabs);
        struct stat out;
        bool outReg = fstat(STDOUT_FILENO, &out) == 0 && S_ISREG(out.st_mode);
        for (int i = 0; i < (g.nops ? g.nops : 1); i++)
            if (!catFile(&c, g.nops ? g.ops[i] : "-", plain, outReg ? &out : NULL)) status = 1;
    }
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("cat", errno);
        status = 1;
    }
    return status;
}
