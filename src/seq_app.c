/*
 * seq: entirely absent before this. Common in shell scripts for simple
 * counting loops (`for i in $(seq 1 10)`).
 *
 * Scope note: -w's zero-padding is verified against real GNU seq for the
 * common integer case, including its sign-aware width quirk (the padding
 * width is the max of the FIRST/LAST operands' raw string lengths, then
 * each value is printed with a standard zero-flag printf -- which
 * naturally reproduces GNU seq's behavior of a negative sign "absorbing"
 * one padding column). Floating-point sequences are supported via a
 * separate double-based path (decimal precision = the max fractional
 * digit count among the given operands, matching real seq's output
 * precision rule), but -w combined with floating-point operands is not
 * specially handled -- an uncommon combination, left as a known gap.
 */

#include "seq_app.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int smallclueSeqFractionDigits(const char *s) {
    const char *dot = strchr(s, '.');
    if (!dot) return 0;
    int n = 0;
    for (const char *p = dot + 1; *p && isdigit((unsigned char)*p); ++p) n++;
    return n;
}

int smallclueSeqCommand(int argc, char **argv) {
    const char *sep = "\n";
    bool widthPad = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        if (strcmp(argv[argi], "-s") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "seq: option requires an argument -- 's'\n");
                return 1;
            }
            sep = argv[++argi];
        } else if (strncmp(argv[argi], "-s", 2) == 0 && argv[argi][2] != '\0') {
            sep = argv[argi] + 2;
        } else if (strcmp(argv[argi], "-w") == 0) {
            widthPad = true;
        } else if (strcmp(argv[argi], "--") == 0) {
            argi++;
            break;
        } else if (argv[argi][0] == '-' && argv[argi][1] != '\0' && !isdigit((unsigned char)argv[argi][1]) && argv[argi][1] != '.') {
            fprintf(stderr, "seq: unsupported option '%s'\n", argv[argi]);
            return 1;
        } else {
            break;
        }
    }

    int operandCount = argc - argi;
    if (operandCount < 1 || operandCount > 3) {
        fprintf(stderr, "usage: seq [-w] [-s SEP] [FIRST [INCREMENT]] LAST\n");
        return 1;
    }
    const char *firstStr = "1";
    const char *incStr = "1";
    const char *lastStr;
    if (operandCount == 1) {
        lastStr = argv[argi];
    } else if (operandCount == 2) {
        firstStr = argv[argi];
        lastStr = argv[argi + 1];
    } else {
        firstStr = argv[argi];
        incStr = argv[argi + 1];
        lastStr = argv[argi + 2];
    }

    bool isFloat = strchr(firstStr, '.') || strchr(incStr, '.') || strchr(lastStr, '.');

    if (isFloat) {
        double first = atof(firstStr);
        double inc = atof(incStr);
        double last = atof(lastStr);
        if (inc == 0.0) {
            fprintf(stderr, "seq: invalid Zero increment value: '%s'\n", incStr);
            return 1;
        }
        int decimals = smallclueSeqFractionDigits(firstStr);
        int d2 = smallclueSeqFractionDigits(incStr);
        int d3 = smallclueSeqFractionDigits(lastStr);
        if (d2 > decimals) decimals = d2;
        if (d3 > decimals) decimals = d3;
        bool firstOut = true;
        for (long long i = 0; ; ++i) {
            double value = first + (double)i * inc;
            if (inc > 0 && value > last + 1e-9) break;
            if (inc < 0 && value < last - 1e-9) break;
            if (!firstOut) fputs(sep, stdout);
            printf("%.*f", decimals, value);
            firstOut = false;
        }
        if (!firstOut) putchar('\n');
        return 0;
    }

    long long first = atoll(firstStr);
    long long inc = atoll(incStr);
    long long last = atoll(lastStr);
    if (inc == 0) {
        fprintf(stderr, "seq: invalid Zero increment value: '%s'\n", incStr);
        return 1;
    }
    int width = 0;
    if (widthPad) {
        int wFirst = (int)strlen(firstStr);
        int wLast = (int)strlen(lastStr);
        width = wFirst > wLast ? wFirst : wLast;
    }
    bool firstOut = true;
    for (long long value = first;
         (inc > 0) ? (value <= last) : (value >= last);
         value += inc) {
        if (!firstOut) fputs(sep, stdout);
        if (widthPad) {
            printf("%0*lld", width, value);
        } else {
            printf("%lld", value);
        }
        firstOut = false;
    }
    if (!firstOut) putchar('\n');
    return 0;
}
