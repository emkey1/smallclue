/*
 * split: entirely absent before this. Splits a file into fixed-size
 * pieces (by line count or byte count) -- used for chunking large files
 * before transfer, or breaking up logs for processing.
 *
 * Scope note: suffix generation is a lowercase base-26 counter starting
 * at "aa" (matching GNU split's default), auto-extending to 3+ letters
 * if more than 26^2 output files are needed rather than erroring --
 * GNU split does the same instead of failing once -z/--numeric-suffixes
 * or a longer -a isn't given.
 */

#include "split_app.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void smallclueSplitSuffix(long long index, int minLen, char *out, size_t outSize) {
    /* Base-26 counter over lowercase letters, like spreadsheet columns
     * but 0-indexed (aa=0, ab=1, ..., az=25, ba=26, ...). Extends to more
     * letters automatically once index overflows minLen digits. */
    int len = minLen;
    long long capacity = 1;
    for (int i = 0; i < len; ++i) capacity *= 26;
    while (index >= capacity) {
        len++;
        capacity *= 26;
    }
    if ((size_t)len >= outSize) len = (int)outSize - 1;
    out[len] = '\0';
    long long v = index;
    for (int i = len - 1; i >= 0; --i) {
        out[i] = (char)('a' + (v % 26));
        v /= 26;
    }
}

static int smallclueSplitWriteChunk(const char *prefix, long long index, const char *data, size_t len) {
    char suffix[16];
    smallclueSplitSuffix(index, 2, suffix, sizeof(suffix));
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", prefix, suffix);
    FILE *out = fopen(path, "wb");
    if (!out) {
        fprintf(stderr, "split: %s: %s\n", path, strerror(errno));
        return 1;
    }
    size_t written = fwrite(data, 1, len, out);
    int status = (written == len) ? 0 : 1;
    if (status) {
        fprintf(stderr, "split: %s: %s\n", path, strerror(errno));
    }
    fclose(out);
    return status;
}

int smallclueSplitCommand(int argc, char **argv) {
    long long linesPerChunk = 0;
    long long bytesPerChunk = 0;
    bool byBytes = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "-l") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "split: option requires an argument -- 'l'\n");
                return 1;
            }
            linesPerChunk = atoll(argv[++argi]);
            byBytes = false;
        } else if (strncmp(arg, "-l", 2) == 0 && arg[2] != '\0') {
            linesPerChunk = atoll(arg + 2);
            byBytes = false;
        } else if (strcmp(arg, "-b") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "split: option requires an argument -- 'b'\n");
                return 1;
            }
            bytesPerChunk = atoll(argv[++argi]);
            byBytes = true;
        } else if (strncmp(arg, "-b", 2) == 0 && arg[2] != '\0') {
            bytesPerChunk = atoll(arg + 2);
            byBytes = true;
        } else if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "split: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (!byBytes && linesPerChunk <= 0) {
        linesPerChunk = 1000; /* GNU split's own default */
    }
    if (byBytes && bytesPerChunk <= 0) {
        fprintf(stderr, "split: invalid number of bytes\n");
        return 1;
    }

    const char *inputPath = (argi < argc) ? argv[argi] : "-";
    const char *prefix = (argi + 1 < argc) ? argv[argi + 1] : "x";

    FILE *in = stdin;
    bool needClose = false;
    if (strcmp(inputPath, "-") != 0) {
        in = fopen(inputPath, "rb");
        if (!in) {
            fprintf(stderr, "split: %s: %s\n", inputPath, strerror(errno));
            return 1;
        }
        needClose = true;
    }

    int status = 0;
    long long chunkIndex = 0;

    if (byBytes) {
        char *buf = (char *)malloc((size_t)bytesPerChunk);
        if (!buf) {
            fprintf(stderr, "split: out of memory\n");
            if (needClose) fclose(in);
            return 1;
        }
        for (;;) {
            size_t got = fread(buf, 1, (size_t)bytesPerChunk, in);
            if (got == 0) break;
            if (smallclueSplitWriteChunk(prefix, chunkIndex++, buf, got) != 0) status = 1;
            if (got < (size_t)bytesPerChunk) break;
        }
        free(buf);
    } else {
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        char *chunkBuf = NULL;
        size_t chunkCap = 0;
        size_t chunkLen = 0;
        long long linesInChunk = 0;
        while ((len = getline(&line, &cap, in)) != -1) {
            if (chunkLen + (size_t)len > chunkCap) {
                size_t newCap = chunkCap ? chunkCap * 2 : 65536;
                while (newCap < chunkLen + (size_t)len) newCap *= 2;
                char *resized = (char *)realloc(chunkBuf, newCap);
                if (!resized) {
                    fprintf(stderr, "split: out of memory\n");
                    free(chunkBuf);
                    free(line);
                    if (needClose) fclose(in);
                    return 1;
                }
                chunkBuf = resized;
                chunkCap = newCap;
            }
            memcpy(chunkBuf + chunkLen, line, (size_t)len);
            chunkLen += (size_t)len;
            linesInChunk++;
            if (linesInChunk >= linesPerChunk) {
                if (smallclueSplitWriteChunk(prefix, chunkIndex++, chunkBuf, chunkLen) != 0) status = 1;
                chunkLen = 0;
                linesInChunk = 0;
            }
        }
        if (chunkLen > 0) {
            if (smallclueSplitWriteChunk(prefix, chunkIndex++, chunkBuf, chunkLen) != 0) status = 1;
        }
        free(chunkBuf);
        free(line);
    }

    if (needClose) fclose(in);
    return status;
}
