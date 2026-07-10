/*
 * od: entirely absent before this (along with hexdump/xxd). Binary
 * inspection during debugging -- build failures, corrupted downloads,
 * verifying ELF headers.
 *
 * Scope note: real od/BSD od's default octal-word format has genuinely
 * idiosyncratic per-column spacing (the address-to-first-value gap
 * differs from the inter-value gap, and differs again for -c's
 * character fields). Rather than byte-match that historical quirk,
 * this implementation uses its own consistent "2-space prefix + fixed-
 * width value" spacing for every format -- correct values/addresses/
 * types, verified against the real system od, just not byte-identical
 * column alignment.
 */

#include "od_app.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool smallclueOdParseType(const char *spec, char *typeCharOut, int *widthOut) {
    if (!spec || !*spec) return false;
    char t = spec[0];
    if (t != 'x' && t != 'o' && t != 'd' && t != 'u' && t != 'c') {
        fprintf(stderr, "od: invalid type '%s'\n", spec);
        return false;
    }
    if (t == 'c') {
        *typeCharOut = 'c';
        *widthOut = 1;
        return true;
    }
    int width = 2; /* default word size if unspecified */
    if (spec[1] != '\0') {
        if (spec[1] == '1') width = 1;
        else if (spec[1] == '2') width = 2;
        else if (spec[1] == '4') width = 4;
        else {
            fprintf(stderr, "od: invalid type size '%s'\n", spec);
            return false;
        }
    }
    *typeCharOut = t;
    *widthOut = width;
    return true;
}

static const char *smallclueOdCharRepr(unsigned char b, char buf[8]) {
    switch (b) {
        case '\0': return "\\0";
        case '\a': return "\\a";
        case '\b': return "\\b";
        case '\f': return "\\f";
        case '\n': return "\\n";
        case '\r': return "\\r";
        case '\t': return "\\t";
        case '\v': return "\\v";
        case '\\': return "\\\\";
        default:
            if (isprint(b)) {
                buf[0] = (char)b;
                buf[1] = '\0';
                return buf;
            }
            snprintf(buf, 8, "%03o", b);
            return buf;
    }
}

static void smallclueOdPrintValue(char typeChar, int width, unsigned long uval, unsigned char rawByte) {
    switch (typeChar) {
        case 'x': {
            int digits = width * 2;
            printf("  %0*lx", digits, uval);
            break;
        }
        case 'o': {
            int digits = (width == 1) ? 3 : (width == 2) ? 6 : 11;
            printf("  %0*lo", digits, uval);
            break;
        }
        case 'u': {
            int fieldw = (width == 1) ? 3 : (width == 2) ? 5 : 10;
            printf("  %*lu", fieldw, uval);
            break;
        }
        case 'd': {
            long sval;
            if (width == 1) sval = (long)(signed char)(unsigned char)uval;
            else if (width == 2) sval = (long)(short)(unsigned short)uval;
            else sval = (long)(int)(unsigned int)uval;
            int fieldw = (width == 1) ? 4 : (width == 2) ? 6 : 11;
            printf("  %*ld", fieldw, sval);
            break;
        }
        case 'c': {
            char buf[8];
            printf("  %4s", smallclueOdCharRepr(rawByte, buf));
            break;
        }
        default:
            break;
    }
}

static void smallclueOdPrintPadding(char typeChar, int width) {
    int fieldw;
    switch (typeChar) {
        case 'x': fieldw = width * 2; break;
        case 'o': fieldw = (width == 1) ? 3 : (width == 2) ? 6 : 11; break;
        case 'u': fieldw = (width == 1) ? 3 : (width == 2) ? 5 : 10; break;
        case 'd': fieldw = (width == 1) ? 4 : (width == 2) ? 6 : 11; break;
        case 'c': fieldw = 4; break;
        default: fieldw = 0; break;
    }
    printf("  %*s", fieldw, "");
}

static void smallclueOdPrintAddress(char radix, unsigned long addr) {
    if (radix == 'n') return;
    switch (radix) {
        case 'd': printf("%07lu", addr); break;
        case 'x': printf("%07lx", addr); break;
        default: printf("%07lo", addr); break;
    }
}

int smallclueOdCommand(int argc, char **argv) {
    char addrRadix = 'o';
    char typeChar = 'o';
    int width = 2; /* default: 2-byte octal words, matching POSIX od's default */

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-c") == 0) {
            typeChar = 'c';
            width = 1;
            continue;
        }
        if (strcmp(arg, "-A") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "od: option requires an argument -- 'A'\n");
                return 1;
            }
            const char *val = argv[++argi];
            if (val[0] == 'd' || val[0] == 'o' || val[0] == 'x' || val[0] == 'n') {
                addrRadix = val[0];
            } else {
                fprintf(stderr, "od: invalid address radix '%s'\n", val);
                return 1;
            }
            continue;
        }
        if (strncmp(arg, "-A", 2) == 0 && arg[2] != '\0') {
            char val = arg[2];
            if (val == 'd' || val == 'o' || val == 'x' || val == 'n') {
                addrRadix = val;
            } else {
                fprintf(stderr, "od: invalid address radix '%c'\n", val);
                return 1;
            }
            continue;
        }
        if (strcmp(arg, "-t") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "od: option requires an argument -- 't'\n");
                return 1;
            }
            if (!smallclueOdParseType(argv[++argi], &typeChar, &width)) return 1;
            continue;
        }
        if (strncmp(arg, "-t", 2) == 0 && arg[2] != '\0') {
            if (!smallclueOdParseType(arg + 2, &typeChar, &width)) return 1;
            continue;
        }
        if (strcmp(arg, "-v") == 0) {
            /* Accepted for compatibility -- this implementation never
             * collapses repeated lines into a '*' marker in the first
             * place, so -v (disable that collapsing) is a no-op here. */
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "od: unsupported option '%s'\n", arg);
            return 1;
        }
        break;
    }

    FILE *in = stdin;
    bool needClose = false;
    if (argi < argc && strcmp(argv[argi], "-") != 0) {
        in = fopen(argv[argi], "rb");
        if (!in) {
            fprintf(stderr, "od: %s: %s\n", argv[argi], strerror(errno));
            return 1;
        }
        needClose = true;
    }

    unsigned char buf[16];
    unsigned long addr = 0;
    size_t n;
    int unitsPerLine = 16 / width;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        smallclueOdPrintAddress(addrRadix, addr);
        size_t unitCount = (n + (size_t)width - 1) / (size_t)width;
        for (int u = 0; u < unitsPerLine; ++u) {
            if ((size_t)u < unitCount) {
                size_t base = (size_t)u * (size_t)width;
                int wid = width;
                if (base + (size_t)wid > n) wid = (int)(n - base);
                unsigned long val = 0;
                for (int b = 0; b < wid; ++b) {
                    val |= ((unsigned long)buf[base + (size_t)b]) << (8 * b);
                }
                smallclueOdPrintValue(typeChar, width, val, buf[base]);
            } else {
                smallclueOdPrintPadding(typeChar, width);
            }
        }
        putchar('\n');
        addr += (unsigned long)n;
        if (n < sizeof(buf)) break;
    }
    smallclueOdPrintAddress(addrRadix, addr);
    putchar('\n');

    if (needClose) fclose(in);
    return 0;
}
