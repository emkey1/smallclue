/*
 * gzip/gunzip/zcat applet. Wraps the zlib already linked into smallclue
 * (CMakeLists.txt's find_package(ZLIB REQUIRED), previously only used
 * internally by libgit2) -- this is "expose an existing dependency as an
 * applet," not "vendor something new."
 */

#include "gzip_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define GZIP_SUFFIX ".gz"
#define GZIP_CHUNK 65536

typedef enum { GZIP_COMPRESS, GZIP_DECOMPRESS } GzipMode;

static bool gzipHasSuffix(const char *name, const char *suffix) {
    size_t nlen = strlen(name);
    size_t slen = strlen(suffix);
    if (nlen < slen) return false;
    return strcmp(name + nlen - slen, suffix) == 0;
}

static bool gzipCopyPlainToGz(FILE *in, gzFile out) {
    char buf[GZIP_CHUNK];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (gzwrite(out, buf, (unsigned)n) != (int)n) {
            fprintf(stderr, "gzip: write error\n");
            return false;
        }
    }
    if (ferror(in)) {
        fprintf(stderr, "gzip: read error\n");
        return false;
    }
    return true;
}

static bool gzipCopyGzToPlain(gzFile in, FILE *out) {
    char buf[GZIP_CHUNK];
    int n;
    while ((n = gzread(in, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t)n, out) != (size_t)n) {
            fprintf(stderr, "gzip: write error\n");
            return false;
        }
    }
    if (n < 0) {
        int errnum = 0;
        const char *msg = gzerror(in, &errnum);
        fprintf(stderr, "gzip: %s\n", msg ? msg : "decompression error");
        return false;
    }
    return true;
}

static int gzipProcessOne(const char *path, GzipMode mode, bool toStdout,
                          bool keepOriginal, bool force) {
    bool isStdin = (!path || strcmp(path, "-") == 0);

    if (mode == GZIP_COMPRESS) {
        char outPath[4096];
        FILE *in = isStdin ? stdin : fopen(path, "rb");
        if (!in) {
            fprintf(stderr, "gzip: %s: %s\n", path, strerror(errno));
            return 1;
        }
        gzFile out;
        if (toStdout || isStdin) {
            out = gzdopen(dup(STDOUT_FILENO), "wb");
        } else {
            if (gzipHasSuffix(path, GZIP_SUFFIX)) {
                fprintf(stderr, "gzip: %s: already has %s suffix -- unchanged\n", path, GZIP_SUFFIX);
                if (in != stdin) fclose(in);
                return 1;
            }
            snprintf(outPath, sizeof(outPath), "%s%s", path, GZIP_SUFFIX);
            if (!force) {
                FILE *exists = fopen(outPath, "rb");
                if (exists) {
                    fclose(exists);
                    fprintf(stderr, "gzip: %s: already exists (use -f to force)\n", outPath);
                    if (in != stdin) fclose(in);
                    return 1;
                }
            }
            out = gzopen(outPath, "wb");
        }
        if (!out) {
            fprintf(stderr, "gzip: failed to open compressed output\n");
            if (in != stdin) fclose(in);
            return 1;
        }
        bool ok = gzipCopyPlainToGz(in, out);
        if (in != stdin) fclose(in);
        gzclose(out);
        if (ok && !toStdout && !isStdin && !keepOriginal) {
            unlink(path);
        }
        return ok ? 0 : 1;
    }

    /* GZIP_DECOMPRESS */
    gzFile in = isStdin ? gzdopen(dup(STDIN_FILENO), "rb") : gzopen(path, "rb");
    if (!in) {
        fprintf(stderr, "gzip: %s: %s\n", path ? path : "(stdin)", strerror(errno));
        return 1;
    }
    FILE *out;
    char outPath[4096];
    bool writingNamedFile = false;
    if (toStdout || isStdin) {
        out = stdout;
    } else {
        if (!gzipHasSuffix(path, GZIP_SUFFIX)) {
            fprintf(stderr, "gzip: %s: unknown suffix -- ignored\n", path);
            gzclose(in);
            return 1;
        }
        size_t plen = strlen(path) - strlen(GZIP_SUFFIX);
        snprintf(outPath, sizeof(outPath), "%.*s", (int)plen, path);
        if (!force) {
            FILE *exists = fopen(outPath, "rb");
            if (exists) {
                fclose(exists);
                fprintf(stderr, "gzip: %s: already exists (use -f to force)\n", outPath);
                gzclose(in);
                return 1;
            }
        }
        out = fopen(outPath, "wb");
        writingNamedFile = true;
        if (!out) {
            fprintf(stderr, "gzip: %s: %s\n", outPath, strerror(errno));
            gzclose(in);
            return 1;
        }
    }
    bool ok = gzipCopyGzToPlain(in, out);
    gzclose(in);
    if (writingNamedFile) fclose(out);
    if (ok && writingNamedFile && !keepOriginal && !isStdin) {
        unlink(path);
    }
    return ok ? 0 : 1;
}

static int gzipRun(int argc, char **argv, GzipMode defaultMode, bool forceStdout,
                   const char *progName) {
    bool toStdout = forceStdout;
    bool keepOriginal = false;
    bool force = false;
    GzipMode mode = defaultMode;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            break;
        }
        for (const char *p = arg + 1; *p; ++p) {
            switch (*p) {
                case 'c': toStdout = true; break;
                case 'k': keepOriginal = true; break;
                case 'f': force = true; break;
                case 'd': mode = GZIP_DECOMPRESS; break;
                default:
                    fprintf(stderr, "%s: unsupported option '%c'\n", progName, *p);
                    return 1;
            }
        }
    }

    int status = 0;
    if (argi >= argc) {
        status |= gzipProcessOne(NULL, mode, true, keepOriginal, force);
    } else {
        for (; argi < argc; ++argi) {
            status |= gzipProcessOne(argv[argi], mode, toStdout, keepOriginal, force);
        }
    }
    return status ? 1 : 0;
}

int smallclueGzipCommand(int argc, char **argv) {
    return gzipRun(argc, argv, GZIP_COMPRESS, false, "gzip");
}

int smallclueGunzipCommand(int argc, char **argv) {
    return gzipRun(argc, argv, GZIP_DECOMPRESS, false, "gunzip");
}

int smallclueZcatCommand(int argc, char **argv) {
    return gzipRun(argc, argv, GZIP_DECOMPRESS, true, "zcat");
}
