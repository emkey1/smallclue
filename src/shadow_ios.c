/*
 * getspnam, lckpwdf and a SHA-512 crypt for the PSCAL app. See ios_shadow.h.
 *
 * The hash is the "SHA-crypt" scheme as published by Ulrich Drepper (sha-crypt.txt, 2007-2008),
 * written here from that specification on OpenSSL's SHA-512.
 */
#if defined(PSCAL_TARGET_IOS) && !defined(__linux__)

#include "ios_shadow.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#define SHADOW_PATH "/etc/shadow"
#define SHADOW_LOCK_PATH "/etc/.pwd.lock"

static long shadowField(const char *text) {
    if (!text || *text == '\0') {
        return -1;
    }
    return strtol(text, NULL, 10);
}

struct spwd *smallclueGetspnam(const char *name) {
    static _Thread_local struct spwd entry;
    static _Thread_local char line[4096];
    if (!name || !*name) {
        errno = EINVAL;
        return NULL;
    }
    FILE *fp = fopen(SHADOW_PATH, "r");
    if (!fp) {
        return NULL;
    }
    size_t name_len = strlen(name);
    struct spwd *found = NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, name, name_len) != 0 || line[name_len] != ':') {
            continue;
        }
        line[strcspn(line, "\r\n")] = '\0';
        /* strsep, not strtok: an empty field is a field, and an empty password is the one that matters. */
        char *cursor = line;
        char *fields[9] = { 0 };
        for (int i = 0; i < 9 && cursor; ++i) {
            fields[i] = strsep(&cursor, ":");
        }
        memset(&entry, 0, sizeof(entry));
        entry.sp_namp = fields[0];
        entry.sp_pwdp = fields[1] ? fields[1] : (char *)"";
        entry.sp_lstchg = shadowField(fields[2]);
        entry.sp_min = shadowField(fields[3]);
        entry.sp_max = shadowField(fields[4]);
        entry.sp_warn = shadowField(fields[5]);
        entry.sp_inact = shadowField(fields[6]);
        entry.sp_expire = shadowField(fields[7]);
        entry.sp_flag = fields[8] && *fields[8] ? strtoul(fields[8], NULL, 10) : 0;
        found = &entry;
        break;
    }
    fclose(fp);
    if (!found) {
        errno = ENOENT;
    }
    return found;
}

/* A lock file, not a host file lock: every task is in one process, and a host lock doesn't keep
 * two of them apart. A lock older than a minute was left by a passwd that never finished. */
int smallclueLckpwdf(void) {
    for (int attempt = 0; attempt < 30; ++attempt) {
        int fd = open(SHADOW_LOCK_PATH, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            close(fd);
            return 0;
        }
        if (errno != EEXIST) {
            return -1;
        }
        struct stat st;
        if (stat(SHADOW_LOCK_PATH, &st) == 0 && time(NULL) - st.st_mtime > 60) {
            unlink(SHADOW_LOCK_PATH);
            continue;
        }
        usleep(500 * 1000);
    }
    errno = EAGAIN;
    return -1;
}

int smallclueUlckpwdf(void) {
    return unlink(SHADOW_LOCK_PATH) == 0 || errno == ENOENT ? 0 : -1;
}

/* --- SHA-512 crypt ------------------------------------------------------------------------- */

#define SHA512_SALT_MAX 16
#define SHA512_ROUNDS_DEFAULT 5000
#define SHA512_ROUNDS_MIN 1000
#define SHA512_ROUNDS_MAX 999999999UL

static const char kCryptItoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char *cryptB64From24(char *out, unsigned b2, unsigned b1, unsigned b0, int n) {
    unsigned w = (b2 << 16) | (b1 << 8) | b0;
    while (n-- > 0) {
        *out++ = kCryptItoa64[w & 0x3f];
        w >>= 6;
    }
    return out;
}

static bool sha512Update(EVP_MD_CTX *ctx, const void *data, size_t len) {
    return EVP_DigestUpdate(ctx, data, len) == 1;
}

char *smallclueCryptSha512(const char *key, const char *setting) {
    static _Thread_local char result[160];
    if (!key || !setting || strncmp(setting, "$6$", 3) != 0) {
        errno = EINVAL;
        return NULL;
    }
    const char *salt = setting + 3;
    unsigned long rounds = SHA512_ROUNDS_DEFAULT;
    bool rounds_custom = false;
    if (strncmp(salt, "rounds=", 7) == 0) {
        char *end = NULL;
        unsigned long value = strtoul(salt + 7, &end, 10);
        if (end && *end == '$') {
            rounds = value < SHA512_ROUNDS_MIN ? SHA512_ROUNDS_MIN
                   : value > SHA512_ROUNDS_MAX ? SHA512_ROUNDS_MAX : value;
            rounds_custom = true;
            salt = end + 1;
        }
    }
    size_t salt_len = strcspn(salt, "$");
    if (salt_len > SHA512_SALT_MAX) {
        salt_len = SHA512_SALT_MAX;
    }
    size_t key_len = strlen(key);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *alt = EVP_MD_CTX_new();
    unsigned char a_result[64];
    unsigned char b_result[64];
    unsigned char *p_bytes = malloc(key_len ? key_len : 1);
    unsigned char s_bytes[SHA512_SALT_MAX];
    unsigned int md_len = 0;
    bool ok = ctx && alt && p_bytes;
    const EVP_MD *md = EVP_sha512();

    /* B = SHA512(key salt key) */
    ok = ok && EVP_DigestInit_ex(alt, md, NULL) == 1 && sha512Update(alt, key, key_len) &&
         sha512Update(alt, salt, salt_len) && sha512Update(alt, key, key_len) &&
         EVP_DigestFinal_ex(alt, b_result, &md_len) == 1;
    /* A = SHA512(key salt B-repeated-to-key-length, then B or key for each bit of the length) */
    ok = ok && EVP_DigestInit_ex(ctx, md, NULL) == 1 && sha512Update(ctx, key, key_len) &&
         sha512Update(ctx, salt, salt_len);
    size_t cnt;
    for (cnt = key_len; ok && cnt > 64; cnt -= 64) {
        ok = sha512Update(ctx, b_result, 64);
    }
    ok = ok && sha512Update(ctx, b_result, cnt);
    for (cnt = key_len; ok && cnt > 0; cnt >>= 1) {
        ok = (cnt & 1) ? sha512Update(ctx, b_result, 64) : sha512Update(ctx, key, key_len);
    }
    ok = ok && EVP_DigestFinal_ex(ctx, a_result, &md_len) == 1;
    /* P: SHA512 of the key key_len times, stretched to key_len bytes. */
    unsigned char dp[64];
    ok = ok && EVP_DigestInit_ex(alt, md, NULL) == 1;
    for (cnt = 0; ok && cnt < key_len; ++cnt) {
        ok = sha512Update(alt, key, key_len);
    }
    ok = ok && EVP_DigestFinal_ex(alt, dp, &md_len) == 1;
    for (cnt = 0; ok && cnt < key_len; ++cnt) {
        p_bytes[cnt] = dp[cnt % 64];
    }
    /* S: SHA512 of the salt 16 + A[0] times, cut to the salt's length. */
    unsigned char ds[64];
    ok = ok && EVP_DigestInit_ex(alt, md, NULL) == 1;
    for (cnt = 0; ok && cnt < 16u + a_result[0]; ++cnt) {
        ok = sha512Update(alt, salt, salt_len);
    }
    ok = ok && EVP_DigestFinal_ex(alt, ds, &md_len) == 1;
    memcpy(s_bytes, ds, salt_len);
    for (unsigned long r = 0; ok && r < rounds; ++r) {
        ok = EVP_DigestInit_ex(ctx, md, NULL) == 1;
        ok = ok && ((r & 1) ? sha512Update(ctx, p_bytes, key_len) : sha512Update(ctx, a_result, 64));
        if (ok && r % 3 != 0) {
            ok = sha512Update(ctx, s_bytes, salt_len);
        }
        if (ok && r % 7 != 0) {
            ok = sha512Update(ctx, p_bytes, key_len);
        }
        ok = ok && ((r & 1) ? sha512Update(ctx, a_result, 64) : sha512Update(ctx, p_bytes, key_len));
        ok = ok && EVP_DigestFinal_ex(ctx, a_result, &md_len) == 1;
    }
    char *out = NULL;
    if (ok) {
        int written = rounds_custom
            ? snprintf(result, sizeof(result), "$6$rounds=%lu$%.*s$", rounds, (int)salt_len, salt)
            : snprintf(result, sizeof(result), "$6$%.*s$", (int)salt_len, salt);
        out = result + written;
        static const unsigned char kOrder[21][3] = {
            {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26},
            {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
            {12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38},
            {18, 39, 60}, {40, 61, 19}, {62, 20, 41},
        };
        for (int i = 0; i < 21; ++i) {
            out = cryptB64From24(out, a_result[kOrder[i][0]], a_result[kOrder[i][1]],
                                 a_result[kOrder[i][2]], 4);
        }
        out = cryptB64From24(out, 0, 0, a_result[63], 2);
        *out = '\0';
    }
    if (p_bytes) {
        memset(p_bytes, 0, key_len ? key_len : 1);
        free(p_bytes);
    }
    memset(a_result, 0, sizeof(a_result));
    memset(b_result, 0, sizeof(b_result));
    memset(dp, 0, sizeof(dp));
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(alt);
    if (!ok) {
        errno = ENOMEM;
        return NULL;
    }
    return result;
}

#endif /* PSCAL_TARGET_IOS && !__linux__ */
