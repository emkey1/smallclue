#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

static void smallclueTrExpandSet(const char *setStr, unsigned char *out, size_t maxLen, size_t *outLen) {
    size_t i = 0, j = 0;
    while (setStr[i] && j < maxLen) {
        if (setStr[i] == '\\' && setStr[i+1]) {
            out[j++] = setStr[i+1];
            i += 2;
        } else if (setStr[i+1] == '-' && setStr[i+2]) {
            unsigned char start = setStr[i];
            unsigned char end = setStr[i+2];
            for (unsigned char c = start; c <= end && j < maxLen; ++c) {
                out[j++] = c;
            }
            i += 3;
        } else {
            out[j++] = setStr[i++];
        }
    }
    *outLen = j;
}

static ssize_t smallclueReadStream(FILE *stream, void *buf, size_t count, int *err) {
    size_t res = fread(buf, 1, count, stream);
    if (res < count && ferror(stream)) {
        if (err) *err = errno;
        return -1;
    }
    return res;
}

int main(int argc, char **argv) {
    bool deleteMode = false, squeezeMode = false, complementMode = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) { argi++; break; }
        if (arg[0] != '-' || arg[1] == '\0') break;
        for (const char *p = arg + 1; *p; ++p) {
            if (*p == 'd') deleteMode = true;
            else if (*p == 's') squeezeMode = true;
            else if (*p == 'c' || *p == 'C') complementMode = true;
            else {
                fprintf(stderr, "tr: unsupported option '%c'\n", *p);
                return 1;
            }
        }
    }
    int operandCount = argc - argi;
    if (operandCount < 1) {
        fprintf(stderr, "tr: missing operand\n");
        return 1;
    }

    unsigned char expanded1[512], expanded2[512];
    size_t len1 = 0, len2 = 0;
    smallclueTrExpandSet(argv[argi], expanded1, sizeof(expanded1), &len1);
    bool haveSet2 = (operandCount >= 2);
    if (haveSet2) {
        smallclueTrExpandSet(argv[argi + 1], expanded2, sizeof(expanded2), &len2);
    }

    if (complementMode) {
        bool inSet[256] = {false};
        for (size_t i = 0; i < len1; ++i) inSet[expanded1[i]] = true;
        size_t newLen = 0;
        for (int c = 0; c < 256; ++c) {
            if (!inSet[c]) expanded1[newLen++] = (unsigned char)c;
        }
        len1 = newLen;
    }

    bool set1Member[256] = {false};
    for (size_t i = 0; i < len1; ++i) set1Member[expanded1[i]] = true;
    bool set2Member[256] = {false};
    for (size_t i = 0; i < len2; ++i) set2Member[expanded2[i]] = true;

    unsigned char map[256];
    for (int i = 0; i < 256; ++i) map[i] = (unsigned char)i;
    if (!deleteMode && haveSet2 && len2 > 0) {
        for (size_t i = 0; i < len1; ++i) {
            unsigned char to = (unsigned char)(i < len2 ? expanded2[i] : expanded2[len2 - 1]);
            map[expanded1[i]] = to;
        }
    } else if (!deleteMode && !haveSet2 && !squeezeMode) {
        fprintf(stderr, "tr: missing operand after '%s'\n", argv[argi]);
        return 1;
    }

    int lastOutput = -1;
    char buf[16384];
    char outBuf[16384];
    ssize_t n;
    int read_err = 0;

    /* Bolt optimization: Fast path for simple translation */
    if (!deleteMode && !squeezeMode && haveSet2) {
        while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
            ssize_t i = 0;
            /* Bolt optimization: Loop unrolling */
            for (; i <= n - 16; i += 16) {
                buf[i]    = map[(unsigned char)buf[i]];
                buf[i+1]  = map[(unsigned char)buf[i+1]];
                buf[i+2]  = map[(unsigned char)buf[i+2]];
                buf[i+3]  = map[(unsigned char)buf[i+3]];
                buf[i+4]  = map[(unsigned char)buf[i+4]];
                buf[i+5]  = map[(unsigned char)buf[i+5]];
                buf[i+6]  = map[(unsigned char)buf[i+6]];
                buf[i+7]  = map[(unsigned char)buf[i+7]];
                buf[i+8]  = map[(unsigned char)buf[i+8]];
                buf[i+9]  = map[(unsigned char)buf[i+9]];
                buf[i+10] = map[(unsigned char)buf[i+10]];
                buf[i+11] = map[(unsigned char)buf[i+11]];
                buf[i+12] = map[(unsigned char)buf[i+12]];
                buf[i+13] = map[(unsigned char)buf[i+13]];
                buf[i+14] = map[(unsigned char)buf[i+14]];
                buf[i+15] = map[(unsigned char)buf[i+15]];
            }
            for (; i < n; ++i) {
                buf[i] = map[(unsigned char)buf[i]];
            }
            fwrite(buf, 1, n, stdout);
        }
        if (read_err) {
            fprintf(stderr, "tr: read error: %s\n", strerror(read_err));
            return 1;
        }
        return 0;
    }

    /* Bolt optimization: Fast path for simple deletion */
    if (deleteMode && !squeezeMode) {
        while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
            size_t outIdx = 0;
            ssize_t i = 0;
            /* Bolt optimization: Loop unrolling with branchless conditional assignments */
            for (; i <= n - 16; i += 16) {
                outBuf[outIdx] = buf[i];    outIdx += !set1Member[(unsigned char)buf[i]];
                outBuf[outIdx] = buf[i+1];  outIdx += !set1Member[(unsigned char)buf[i+1]];
                outBuf[outIdx] = buf[i+2];  outIdx += !set1Member[(unsigned char)buf[i+2]];
                outBuf[outIdx] = buf[i+3];  outIdx += !set1Member[(unsigned char)buf[i+3]];
                outBuf[outIdx] = buf[i+4];  outIdx += !set1Member[(unsigned char)buf[i+4]];
                outBuf[outIdx] = buf[i+5];  outIdx += !set1Member[(unsigned char)buf[i+5]];
                outBuf[outIdx] = buf[i+6];  outIdx += !set1Member[(unsigned char)buf[i+6]];
                outBuf[outIdx] = buf[i+7];  outIdx += !set1Member[(unsigned char)buf[i+7]];
                outBuf[outIdx] = buf[i+8];  outIdx += !set1Member[(unsigned char)buf[i+8]];
                outBuf[outIdx] = buf[i+9];  outIdx += !set1Member[(unsigned char)buf[i+9]];
                outBuf[outIdx] = buf[i+10]; outIdx += !set1Member[(unsigned char)buf[i+10]];
                outBuf[outIdx] = buf[i+11]; outIdx += !set1Member[(unsigned char)buf[i+11]];
                outBuf[outIdx] = buf[i+12]; outIdx += !set1Member[(unsigned char)buf[i+12]];
                outBuf[outIdx] = buf[i+13]; outIdx += !set1Member[(unsigned char)buf[i+13]];
                outBuf[outIdx] = buf[i+14]; outIdx += !set1Member[(unsigned char)buf[i+14]];
                outBuf[outIdx] = buf[i+15]; outIdx += !set1Member[(unsigned char)buf[i+15]];
            }
            for (; i < n; ++i) {
                outBuf[outIdx] = buf[i];
                outIdx += !set1Member[(unsigned char)buf[i]];
            }
            if (outIdx > 0) {
                fwrite(outBuf, 1, outIdx, stdout);
            }
        }
        if (read_err) {
            fprintf(stderr, "tr: read error: %s\n", strerror(read_err));
            return 1;
        }
        return 0;
    }

    while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
        size_t outIdx = 0;
        for (ssize_t i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            bool squeezeCandidate;
            if (deleteMode) {
                if (set1Member[c]) continue;
                squeezeCandidate = squeezeMode && haveSet2 && set2Member[c];
            } else if (haveSet2) {
                c = map[c];
                squeezeCandidate = squeezeMode && set2Member[c];
            } else {
                /* squeeze-only, no translation */
                squeezeCandidate = squeezeMode && set1Member[c];
            }
            if (squeezeCandidate && lastOutput == (int)c) {
                continue;
            }
            outBuf[outIdx++] = (char)c;
            lastOutput = squeezeCandidate ? (int)c : -1;
        }
        if (outIdx > 0) {
            fwrite(outBuf, 1, outIdx, stdout);
        }
    }

    if (read_err) {
        fprintf(stderr, "tr: read error: %s\n", strerror(read_err));
        return 1;
    }
    return 0;
}
