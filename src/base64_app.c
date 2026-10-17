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
    unsigned char in_buf[16384];
    unsigned char out_buf[32768];
    size_t out_len = 0;
    size_t n;
    int col = 0;
    unsigned char carry[2];
    size_t carry_len = 0;

    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        size_t i = 0;

        // Process carry from last block if any
        if (carry_len > 0) {
            unsigned char b0, b1, b2;
            size_t total_avail = carry_len + n;

            b0 = carry[0];
            b1 = (carry_len == 2) ? carry[1] : in_buf[i++];
            b2 = (total_avail > 2) ? in_buf[i++] : 0;

            if (total_avail >= 3) {
                char out4[4];
                out4[0] = kBase64Chars[b0 >> 2];
                out4[1] = kBase64Chars[((b0 & 0x3) << 4) | (b1 >> 4)];
                out4[2] = kBase64Chars[((b1 & 0xF) << 2) | (b2 >> 6)];
                out4[3] = kBase64Chars[b2 & 0x3F];

                for (int j = 0; j < 4; j++) {
                    out_buf[out_len++] = out4[j];
                    col++;
                    if (wrapCol > 0 && col == wrapCol) {
                        out_buf[out_len++] = '\n';
                        col = 0;
                    }
                }
                carry_len = 0;
            } else {
                // Still not enough (very rare, e.g. read only 1 byte and had 1 carry)
                if (i < n) carry[carry_len++] = in_buf[i++];
                continue; // Wait for more
            }
        }

        // Process main block
        while (i + 2 < n) {
            unsigned char b0 = in_buf[i];
            unsigned char b1 = in_buf[i+1];
            unsigned char b2 = in_buf[i+2];
            i += 3;

            char out4[4];
            out4[0] = kBase64Chars[b0 >> 2];
            out4[1] = kBase64Chars[((b0 & 0x3) << 4) | (b1 >> 4)];
            out4[2] = kBase64Chars[((b1 & 0xF) << 2) | (b2 >> 6)];
            out4[3] = kBase64Chars[b2 & 0x3F];

            for (int j = 0; j < 4; j++) {
                out_buf[out_len++] = out4[j];
                col++;
                if (wrapCol > 0 && col == wrapCol) {
                    out_buf[out_len++] = '\n';
                    col = 0;
                }
            }

            if (out_len >= sizeof(out_buf) - 5) {
                fwrite(out_buf, 1, out_len, out);
                out_len = 0;
            }
        }

        // Save remaining bytes to carry
        while (i < n) {
            carry[carry_len++] = in_buf[i++];
        }
    }

    // Process final carry
    if (carry_len > 0) {
        unsigned char b0 = carry[0];
        unsigned char b1 = (carry_len > 1) ? carry[1] : 0;

        char out4[4];
        out4[0] = kBase64Chars[b0 >> 2];
        out4[1] = kBase64Chars[((b0 & 0x3) << 4) | (b1 >> 4)];
        out4[2] = (carry_len > 1) ? kBase64Chars[((b1 & 0xF) << 2)] : '=';
        out4[3] = '=';

        for (int j = 0; j < 4; j++) {
            out_buf[out_len++] = out4[j];
            col++;
            if (wrapCol > 0 && col == wrapCol) {
                out_buf[out_len++] = '\n';
                col = 0;
            }
        }
    }

    if (out_len > 0) {
        fwrite(out_buf, 1, out_len, out);
    }
    if (wrapCol > 0 && col != 0) {
        fputc('\n', out);
    }
    return ferror(in) ? 1 : 0;
}

static int smallclueBase64Decode(FILE *in, FILE *out, bool ignoreGarbage) {
    unsigned char in_buf[16384];
    unsigned char out_buf[16384];
    size_t out_len = 0;
    int vals[4];
    int count = 0;
    size_t n;
    bool pad_found = false;

    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        size_t i;
        for (i = 0; i < n; i++) {
            char c = in_buf[i];
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            if (c == '=') {
                pad_found = true;
                break;
            }
            int v = smallclueBase64DecodeChar(c);
            if (v < 0) {
                if (ignoreGarbage) continue;
                if (out_len > 0) fwrite(out_buf, 1, out_len, out);
                fprintf(stderr, "base64: invalid input\n");
                return 1;
            }
            vals[count++] = v;
            if (count == 4) {
                out_buf[out_len++] = (vals[0] << 2) | (vals[1] >> 4);
                out_buf[out_len++] = ((vals[1] & 0xF) << 4) | (vals[2] >> 2);
                out_buf[out_len++] = ((vals[2] & 0x3) << 6) | vals[3];
                count = 0;
                if (out_len >= sizeof(out_buf) - 3) {
                    fwrite(out_buf, 1, out_len, out);
                    out_len = 0;
                }
            }
        }
        if (pad_found) {
            // Consume remaining padding/whitespace up to the next real character
            i++; // skip the '=' we just found
            for (; i < n; i++) {
                char c = in_buf[i];
                if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
                break; // found a real character, so break.
            }
            // if we exhausted this buffer, we'd need to consume stream.
            // But realistically we just break out since we are done decoding.
            break;
        }
    }

    // Original logic consumes stream until next non-whitespace/padding character
    if (pad_found) {
        int c;
        while ((c = fgetc(in)) != EOF) {
            if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            break;
        }
    }

    if (out_len > 0) {
        fwrite(out_buf, 1, out_len, out);
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
