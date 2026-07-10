/*
 * base64: entirely absent before this. Checksum verification of
 * downloaded artifacts and encoding binary data for text-only transport
 * (e.g. embedding into JSON/env vars) are standard practice; nothing
 * in this codebase produced or consumed base64.
 */

#include "base64_app.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int smallclueBase64DecodeChar(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int smallclueBase64Encode(FILE *in, FILE *out, int wrapCol) {
    unsigned char buf[3];
    size_t n;
    int col = 0;
    while ((n = fread(buf, 1, 3, in)) > 0) {
        unsigned char b0 = buf[0];
        unsigned char b1 = (n > 1) ? buf[1] : 0;
        unsigned char b2 = (n > 2) ? buf[2] : 0;
        char out4[4];
        out4[0] = kBase64Chars[b0 >> 2];
        out4[1] = kBase64Chars[((b0 & 0x3) << 4) | (b1 >> 4)];
        out4[2] = (n > 1) ? kBase64Chars[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out4[3] = (n > 2) ? kBase64Chars[b2 & 0x3F] : '=';
        for (int i = 0; i < 4; ++i) {
            fputc(out4[i], out);
            col++;
            if (wrapCol > 0 && col == wrapCol) {
                fputc('\n', out);
                col = 0;
            }
        }
    }
    if (wrapCol > 0 && col != 0) {
        fputc('\n', out);
    }
    return ferror(in) ? 1 : 0;
}

static int smallclueBase64Decode(FILE *in, FILE *out, bool ignoreGarbage) {
    int c = EOF;
    int vals[4];
    int count = 0;
    while ((c = fgetc(in)) != EOF) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = smallclueBase64DecodeChar((char)c);
        if (v < 0) {
            if (ignoreGarbage) continue;
            fprintf(stderr, "base64: invalid input\n");
            return 1;
        }
        vals[count++] = v;
        if (count == 4) {
            fputc((vals[0] << 2) | (vals[1] >> 4), out);
            fputc(((vals[1] & 0xF) << 4) | (vals[2] >> 2), out);
            fputc(((vals[2] & 0x3) << 6) | vals[3], out);
            count = 0;
        }
    }
    if (c == '=') {
        /* Consume any remaining padding/whitespace up to the next real
         * character (there shouldn't be one in well-formed input). */
        while ((c = fgetc(in)) != EOF) {
            if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            break;
        }
    }
    if (count == 2) {
        fputc((vals[0] << 2) | (vals[1] >> 4), out);
    } else if (count == 3) {
        fputc((vals[0] << 2) | (vals[1] >> 4), out);
        fputc(((vals[1] & 0xF) << 4) | (vals[2] >> 2), out);
    } else if (count == 1) {
        fprintf(stderr, "base64: invalid input\n");
        return 1;
    }
    return 0;
}

int smallclueBase64Command(int argc, char **argv) {
    bool decode = false;
    bool ignoreGarbage = false;
    int wrapCol = 76;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-d") == 0 || strcmp(arg, "--decode") == 0) {
            decode = true;
            continue;
        }
        if (strcmp(arg, "-i") == 0 || strcmp(arg, "--ignore-garbage") == 0) {
            ignoreGarbage = true;
            continue;
        }
        if (strcmp(arg, "-w") == 0 || strcmp(arg, "--wrap") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "base64: option '%s' requires an argument\n", arg);
                return 1;
            }
            wrapCol = atoi(argv[++argi]);
            continue;
        }
        if (strncmp(arg, "--wrap=", 7) == 0) {
            wrapCol = atoi(arg + 7);
            continue;
        }
        if (strncmp(arg, "-w", 2) == 0 && isdigit((unsigned char)arg[2])) {
            wrapCol = atoi(arg + 2);
            continue;
        }
        if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "base64: unsupported option '%s'\n", arg);
            return 1;
        }
        break;
    }

    FILE *in = stdin;
    bool needClose = false;
    if (argi < argc && strcmp(argv[argi], "-") != 0) {
        in = fopen(argv[argi], "rb");
        if (!in) {
            fprintf(stderr, "base64: %s: %s\n", argv[argi], strerror(errno));
            return 1;
        }
        needClose = true;
    }

    int status = decode ? smallclueBase64Decode(in, stdout, ignoreGarbage)
                         : smallclueBase64Encode(in, stdout, wrapCol);
    if (needClose) {
        fclose(in);
    }
    return status;
}
