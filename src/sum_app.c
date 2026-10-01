/*
 * sum: GNU coreutils 9 compatible. The BSD checksum ("%05d %5s", 1K
 * blocks; -r, the default) and the System V one ("%d %s", 512-byte blocks;
 * -s/--sysv), the last option winning; a name after the counts whenever a
 * FILE operand was given ("-" included); read errors reported and counted.
 */

#include "sum_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* false on a read error (errno set). */
static bool sumFile(FILE *f, bool sysv, unsigned *checksum, unsigned long long *bytes) {
    unsigned char buf[65536];
    uint32_t s = 0;
    unsigned long long total = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (sysv) {
            for (size_t i = 0; i < n; i++) s += buf[i];
        } else {
            for (size_t i = 0; i < n; i++) {
                s = (s >> 1) | ((s & 1) << 15);
                s = (s + buf[i]) & 0xffff;
            }
        }
        total += n;
    }
    if (ferror(f)) return false;
    if (sysv) {
        uint32_t r = (s & 0xffff) + ((s & 0xffffffff) >> 16);
        s = (r & 0xffff) + (r >> 16);
    }
    *checksum = s;
    *bytes = total;
    return true;
}

static const GnuLongOpt sumLongs[] = {
    {"sysv", GNU_NO_ARG, 's'}, {"help", GNU_NO_ARG, 1}, {"version", GNU_NO_ARG, 2},
};

int smallclueSumCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "sum", "rs", sumLongs, sizeof(sumLongs) / sizeof(sumLongs[0]));
    bool sysv = false;
    int c, status = 0;
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'r': sysv = false; break;
        case 's': sysv = true; break;
        case 1:
            fputs("Usage: sum [OPTION]... [FILE]...\n"
                  "Print or check BSD (16-bit) checksums.\n\n"
                  "With no FILE, or when FILE is -, read standard input.\n\n"
                  "  -r              use BSD sum algorithm (the default), use 1K blocks\n"
                  "  -s, --sysv      use System V sum algorithm, use 512 bytes blocks\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            goto done;
        case 2: puts("sum (SmallCLUE) 9.4"); goto done;
        default:
            fputs("Try 'sum --help' for more information.\n", stderr);
            status = 1;
            goto done;
        }
    }
    for (int i = 0; i < (g.nops ? g.nops : 1); i++) {
        const char *name = g.nops ? g.ops[i] : "-";
        bool isStdin = !strcmp(name, "-");
        FILE *f = isStdin ? stdin : smallclueAppOpenRead(name);
        if (!f) {
            fprintf(stderr, "sum: %s: %s\n", name, strerror(errno));
            status = 1;
            continue;
        }
        unsigned sum = 0;
        unsigned long long bytes = 0;
        bool ok = sumFile(f, sysv, &sum, &bytes);
        int err = errno;
        if (isStdin) clearerr(stdin);
        else fclose(f);
        if (!ok) {
            fprintf(stderr, "sum: %s: %s\n", name, strerror(err));
            status = 1;
            continue;
        }
        if (sysv) printf("%u %llu", sum, (bytes + 511) / 512);
        else printf("%05u %5llu", sum, (bytes + 1023) / 1024);
        if (g.nops) printf(" %s", name);
        putchar('\n');
    }
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("sum", errno);
        status = 1;
    }
    return status;
}
