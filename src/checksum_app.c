/*
 * md5sum/sha1sum/sha256sum applet. Wraps the OpenSSL EVP digest API
 * already linked into smallclue (CMakeLists.txt's find_package(OpenSSL
 * REQUIRED), used internally by libgit2/openssh) -- exposing an existing
 * dependency as an applet, same pattern as gzip/tar and zlib.
 *
 * "sum" (BSD/SysV checksum) already exists but isn't a substitute:
 * nothing in the tree previously produced an MD5/SHA digest, and
 * checksum verification of downloaded artifacts is standard practice.
 */

#include "checksum_app.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

typedef enum { CHECKSUM_MD5, CHECKSUM_SHA1, CHECKSUM_SHA256 } ChecksumAlgo;

static const EVP_MD *smallclueChecksumMd(ChecksumAlgo algo) {
    switch (algo) {
        case CHECKSUM_MD5: return EVP_md5();
        case CHECKSUM_SHA1: return EVP_sha1();
        case CHECKSUM_SHA256: return EVP_sha256();
    }
    return NULL;
}

static const char *smallclueChecksumName(ChecksumAlgo algo) {
    switch (algo) {
        case CHECKSUM_MD5: return "md5sum";
        case CHECKSUM_SHA1: return "sha1sum";
        case CHECKSUM_SHA256: return "sha256sum";
    }
    return "checksum";
}

static bool smallclueChecksumDigestStream(FILE *fp, ChecksumAlgo algo, unsigned char *digest, unsigned int *digestLen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, smallclueChecksumMd(algo), NULL) == 1;
    char buf[65536];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        ok = EVP_DigestUpdate(ctx, buf, n) == 1;
    }
    if (ok && ferror(fp)) {
        ok = false;
    }
    if (ok) {
        ok = EVP_DigestFinal_ex(ctx, digest, digestLen) == 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void smallclueChecksumHexEncode(const unsigned char *digest, unsigned int len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; ++i) {
        out[i * 2] = hex[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[digest[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static int smallclueChecksumOne(const char *path, ChecksumAlgo algo, char *hexOut) {
    FILE *fp = path ? fopen(path, "rb") : stdin;
    if (!fp) {
        fprintf(stderr, "%s: %s: %s\n", smallclueChecksumName(algo), path, strerror(errno));
        return 1;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    bool ok = smallclueChecksumDigestStream(fp, algo, digest, &digestLen);
    if (fp != stdin) fclose(fp);
    if (!ok) {
        fprintf(stderr, "%s: %s: digest computation failed\n", smallclueChecksumName(algo), path ? path : "(stdin)");
        return 1;
    }
    smallclueChecksumHexEncode(digest, digestLen, hexOut);
    return 0;
}

/* -c/--check: verify against a checksums file in the standard
 * "HEXDIGEST  path" format (two spaces = text mode, one space + '*' = binary
 * mode -- both accepted identically here since there's no meaningful
 * text/binary distinction in this implementation). */
static int smallclueChecksumCheck(const char *sumsPath, ChecksumAlgo algo) {
    FILE *fp = sumsPath ? fopen(sumsPath, "r") : stdin;
    if (!fp) {
        fprintf(stderr, "%s: %s: %s\n", smallclueChecksumName(algo), sumsPath, strerror(errno));
        return 1;
    }
    int status = 0;
    int checked = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, fp)) >= 0) {
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;
        char *sep = strstr(line, "  ");
        char *filePart;
        if (sep) {
            *sep = '\0';
            filePart = sep + 2;
        } else if ((sep = strstr(line, " *")) != NULL) {
            *sep = '\0';
            filePart = sep + 2;
        } else {
            fprintf(stderr, "%s: malformed checksum line: %s\n", smallclueChecksumName(algo), line);
            status = 1;
            continue;
        }
        char actual[EVP_MAX_MD_SIZE * 2 + 1];
        if (smallclueChecksumOne(filePart, algo, actual) != 0) {
            status = 1;
            continue;
        }
        checked++;
        if (strcasecmp(actual, line) == 0) {
            printf("%s: OK\n", filePart);
        } else {
            printf("%s: FAILED\n", filePart);
            status = 1;
        }
    }
    free(line);
    if (fp != stdin) fclose(fp);
    if (checked == 0) {
        fprintf(stderr, "%s: no properly formatted checksum lines found\n", smallclueChecksumName(algo));
        return 1;
    }
    return status;
}

static int smallclueChecksumRun(int argc, char **argv, ChecksumAlgo algo) {
    bool checkMode = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--check") == 0) {
            checkMode = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "%s: unsupported option '%s'\n", smallclueChecksumName(algo), arg);
            return 1;
        } else {
            break;
        }
    }

    if (checkMode) {
        if (argi >= argc) {
            return smallclueChecksumCheck(NULL, algo);
        }
        int status = 0;
        for (int i = argi; i < argc; ++i) {
            if (smallclueChecksumCheck(argv[i], algo) != 0) status = 1;
        }
        return status;
    }

    if (argi >= argc) {
        char hex[EVP_MAX_MD_SIZE * 2 + 1];
        if (smallclueChecksumOne(NULL, algo, hex) != 0) return 1;
        printf("%s  -\n", hex);
        return 0;
    }
    int status = 0;
    for (int i = argi; i < argc; ++i) {
        char hex[EVP_MAX_MD_SIZE * 2 + 1];
        if (smallclueChecksumOne(argv[i], algo, hex) != 0) {
            status = 1;
            continue;
        }
        printf("%s  %s\n", hex, argv[i]);
    }
    return status;
}

int smallclueMd5sumCommand(int argc, char **argv) {
    return smallclueChecksumRun(argc, argv, CHECKSUM_MD5);
}

int smallclueSha1sumCommand(int argc, char **argv) {
    return smallclueChecksumRun(argc, argv, CHECKSUM_SHA1);
}

int smallclueSha256sumCommand(int argc, char **argv) {
    return smallclueChecksumRun(argc, argv, CHECKSUM_SHA256);
}
