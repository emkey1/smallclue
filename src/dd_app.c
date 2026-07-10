/*
 * dd: entirely absent before this. Low-level block copy -- image
 * manipulation, zeroing, /dev/zero/urandom-sourced writes.
 */

#include "dd_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long long smallclueDdParseSize(const char *s) {
    char *end = NULL;
    long long val = strtoll(s, &end, 10);
    if (end) {
        if (*end == 'k' || *end == 'K') val *= 1024;
        else if (*end == 'M' || *end == 'm') val *= 1024LL * 1024;
        else if (*end == 'G' || *end == 'g') val *= 1024LL * 1024 * 1024;
        else if (*end == 'b') val *= 512;
        else if (*end == 'w') val *= 2;
    }
    return val;
}

int smallclueDdCommand(int argc, char **argv) {
    const char *inPath = NULL;
    const char *outPath = NULL;
    long long bs = 512;
    long long count = -1; /* -1 = until EOF */
    long long skip = 0;
    long long seek = 0;
    bool notrunc = false;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strncmp(arg, "if=", 3) == 0) {
            inPath = arg + 3;
        } else if (strncmp(arg, "of=", 3) == 0) {
            outPath = arg + 3;
        } else if (strncmp(arg, "bs=", 3) == 0) {
            bs = smallclueDdParseSize(arg + 3);
        } else if (strncmp(arg, "count=", 6) == 0) {
            count = smallclueDdParseSize(arg + 6);
        } else if (strncmp(arg, "skip=", 5) == 0) {
            skip = smallclueDdParseSize(arg + 5);
        } else if (strncmp(arg, "seek=", 5) == 0) {
            seek = smallclueDdParseSize(arg + 5);
        } else if (strncmp(arg, "conv=", 5) == 0) {
            if (strstr(arg + 5, "notrunc")) notrunc = true;
        } else {
            fprintf(stderr, "dd: unrecognized operand '%s'\n", arg);
            return 1;
        }
    }
    if (bs <= 0) {
        fprintf(stderr, "dd: invalid block size\n");
        return 1;
    }

    FILE *in = inPath ? fopen(inPath, "rb") : stdin;
    if (!in) {
        fprintf(stderr, "dd: %s: %s\n", inPath, strerror(errno));
        return 1;
    }

    FILE *out;
    if (outPath) {
        out = fopen(outPath, notrunc ? "r+b" : "wb");
        if (!out && notrunc && errno == ENOENT) {
            /* notrunc but the file doesn't exist yet -- create it. */
            out = fopen(outPath, "wb");
        }
        if (!out) {
            fprintf(stderr, "dd: %s: %s\n", outPath, strerror(errno));
            if (inPath) fclose(in);
            return 1;
        }
    } else {
        out = stdout;
    }

    char *buf = (char *)malloc((size_t)bs);
    if (!buf) {
        fprintf(stderr, "dd: out of memory\n");
        if (inPath) fclose(in);
        if (outPath) fclose(out);
        return 1;
    }

    if (skip > 0) {
        if (fseeko(in, skip * bs, SEEK_SET) != 0) {
            /* Not seekable (a pipe) -- fall back to reading and
             * discarding the skipped blocks. */
            for (long long i = 0; i < skip; ++i) {
                size_t n = fread(buf, 1, (size_t)bs, in);
                if (n == 0) break;
            }
        }
    }
    if (seek > 0) {
        if (fseeko(out, seek * bs, SEEK_SET) != 0) {
            fprintf(stderr, "dd: cannot seek output: %s\n", strerror(errno));
            free(buf);
            if (inPath) fclose(in);
            if (outPath) fclose(out);
            return 1;
        }
    }

    long long fullIn = 0, partialIn = 0;
    long long fullOut = 0, partialOut = 0;
    long long bytesTotal = 0;
    long long blocksCopied = 0;
    int status = 0;

    while (count < 0 || blocksCopied < count) {
        size_t n = fread(buf, 1, (size_t)bs, in);
        if (n == 0) break;
        if (n == (size_t)bs) fullIn++; else partialIn++;

        size_t written = fwrite(buf, 1, n, out);
        if (written == (size_t)bs) fullOut++;
        else if (written > 0) partialOut++;
        bytesTotal += (long long)written;
        if (written < n) {
            fprintf(stderr, "dd: write error: %s\n", strerror(errno));
            status = 1;
            break;
        }

        blocksCopied++;
        if (n < (size_t)bs) break; /* short read: input exhausted */
    }
    if (ferror(in)) {
        fprintf(stderr, "dd: read error: %s\n", strerror(errno));
        status = 1;
    }
    fflush(out);

    fprintf(stderr, "%lld+%lld records in\n", fullIn, partialIn);
    fprintf(stderr, "%lld+%lld records out\n", fullOut, partialOut);
    fprintf(stderr, "%lld bytes transferred\n", bytesTotal);

    free(buf);
    if (inPath) fclose(in);
    if (outPath) fclose(out);
    return status;
}
