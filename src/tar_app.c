/*
 * tar: GNU tar 1.35 compatible. Reads ustar, GNU (L/K long names) and pax
 * (x/g records: path, linkpath, size, mtime, uid, gid, uname, gname)
 * archives, numbers octal or base-256, with gzip/bzip2/xz/zstd/lzip/lzma/
 * compress detected by magic; writes GNU format in 10240-byte records with
 * hard links found. -c -x -t -r -u; the old bundled syntax (tar cvzf ...);
 * -f, -C in order, -v/-vv listings GNU's way, -z -j -J -Z -a -I and the
 * long compressor options, -O, -k, --skip-old-files, -p, -m, -h, -P,
 * --strip-components, --exclude/-X/-T/--null, --no-recursion, --owner,
 * --group, --numeric-owner, --mode, --mtime, --no-same-owner,
 * --no-same-permissions, --remove-files, --wildcards, --ignore-zeros,
 * --totals; GNU's messages and its 0/2 exit statuses.
 */

#include "tar_app.h"

#include "gnu_getopt.h"
#include "gnu_mode.h"
#include "gnu_util.h"
#include "date_app.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#if !defined(__APPLE__)
#include <sys/sysmacros.h>
#endif
#ifndef FNM_LEADING_DIR
#define FNM_LEADING_DIR 0
#endif

#define TAR_BLOCK 512
#define TAR_RECORD 10240

typedef struct {
    char name[100], mode[8], uid[8], gid[8], size[12], mtime[12], chksum[8], typeflag, linkname[100];
    char magic[6], version[2], uname[32], gname[32], devmajor[8], devminor[8], prefix[155], pad[12];
} TarHeader;

/* --- The archive stream: a descriptor, zlib, or a compressor child. --- */

typedef struct {
    int fd;              /* raw archive, or -1 */
    FILE *pipe;          /* a compressor's other end */
    bool gzip, writing, eof;
    z_stream z;
    unsigned char zbuf[65536];
    uLong crc;
    uintmax_t rawLen;
    unsigned char peek[512];
    size_t npeek, peekPos;
    uintmax_t total;     /* bytes through, uncompressed */
} TarIo;

typedef struct Tar Tar;

struct TarLinkSeen {
    dev_t dev;
    ino_t ino;
    char *name;
};

struct TarDelayed {
    char *path;
    mode_t mode;
    struct timespec mtime;
    uid_t uid;
    gid_t gid;
    bool owner;
};

struct Tar {
    int op;
    const char *archive;
    int verbose;
    int compress;                 /* 0 'z' 'j' 'J' 'Z' 'L'(lzip) 'M'(lzma) 'O'(lzop) 'S'(zstd) 'I' */
    const char *compressProg;
    bool autoCompress, toStdout, keepOld, skipOld, absolute, deref, noRecursion, numericOwner;
    int sameOwner, samePerms;     /* -1: by euid */
    bool noMtime, removeFiles, nullNames, wildcards, ignoreZeros, totals;
    intmax_t strip;
    char **excludes;
    size_t nexcludes;
    const char *ownerName, *groupName;
    bool ownerSet, groupSet;
    uid_t ownerUid;
    gid_t ownerGid;
    GnuMode modeChange;
    bool modeSet, mtimeSet;
    struct timespec mtimeValue;
    int status;
    bool fatal;          /* "Error is not recoverable" already said */
    bool warnedSlash, warnedDotdot;
    FILE *listOut;
    TarIo io;
    struct TarLinkSeen *links;
    size_t nlinks;
    struct TarDelayed *delayed;
    size_t ndelayed;
    struct stat archiveSt;
    bool archiveStOk;
    mode_t umaskValue;
    /* pax globals */
    char *gUname, *gGname;
};

static void tarErr(Tar *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void tarErr(Tar *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("tar: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    t->status = 2;
}

static void tarFatal(Tar *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void tarFatal(Tar *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("tar: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    fputs("tar: Error is not recoverable: exiting now\n", stderr);
    t->status = 2;
    t->fatal = true;
}

static const char *tarProgram(int c, const char *prog) {
    switch (c) {
    case 'j': return "bzip2";
    case 'J': return "xz";
    case 'Z': return "compress";
    case 'L': return "lzip";
    case 'M': return "lzma";
    case 'O': return "lzop";
    case 'S': return "zstd";
    case 'I': return prog;
    default: return NULL;
    }
}

/* 'path' quoted for sh. */
static char *tarShellQuote(const char *s) {
    size_t n = strlen(s);
    char *o = (char *)malloc(n * 4 + 3), *p = o;
    *p++ = '\'';
    for (; *s; s++) {
        if (*s == '\'') {
            memcpy(p, "'\\''", 4);
            p += 4;
        } else {
            *p++ = *s;
        }
    }
    *p++ = '\'';
    *p = '\0';
    return o;
}

/* GNU tar runs a compressor as /bin/sh -c, and the shell's errors name it so. */
static FILE *tarPopen(const char *cmd, const char *mode) {
    char *q = tarShellQuote(cmd);
    size_t n = strlen(q) + 32;
    char *full = (char *)malloc(n);
    snprintf(full, n, "exec /bin/sh -c %s", q);
    FILE *f = popen(full, mode);
    free(q);
    free(full);
    return f;
}

static bool tarIoOpenWrite(Tar *t, int fd) {
    TarIo *io = &t->io;
    memset(io, 0, sizeof(*io));
    io->writing = true;
    io->fd = fd;
    if (t->compress == 'z') {
        io->gzip = true;
        static const unsigned char hdr[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
        if (write(fd, hdr, 10) != 10) return false;
        if (deflateInit2(&io->z, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return false;
        io->crc = crc32(0, NULL, 0);
    } else if (t->compress) {
        const char *prog = tarProgram(t->compress, t->compressProg);
        char cmd[4096];
        if (fd == STDOUT_FILENO) {
            snprintf(cmd, sizeof(cmd), "%s", prog);
        } else {
            /* the child writes the archive; we drop our descriptor */
            char *q = tarShellQuote(t->archive);
            snprintf(cmd, sizeof(cmd), "%s > %s", prog, q);
            free(q);
            close(fd);
            io->fd = -1;
        }
        fflush(stdout);
        io->pipe = tarPopen(cmd, "w");
        if (!io->pipe) return false;
    }
    return true;
}

static bool tarWriteFd(int fd, const void *b, size_t n) {
    const unsigned char *p = (const unsigned char *)b;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

static bool tarIoWrite(Tar *t, const void *b, size_t n) {
    TarIo *io = &t->io;
    io->total += n;
    if (io->pipe) return fwrite(b, 1, n, io->pipe) == n;
    if (!io->gzip) return tarWriteFd(io->fd, b, n);
    io->crc = crc32(io->crc, (const Bytef *)b, (uInt)n);
    io->rawLen += n;
    io->z.next_in = (Bytef *)b;
    io->z.avail_in = (uInt)n;
    do {
        io->z.next_out = io->zbuf;
        io->z.avail_out = sizeof(io->zbuf);
        deflate(&io->z, Z_NO_FLUSH);
        if (!tarWriteFd(io->fd, io->zbuf, sizeof(io->zbuf) - io->z.avail_out)) return false;
    } while (io->z.avail_out == 0);
    return true;
}

/* Finish the stream; false (after GNU's message) when the compressor failed. */
static bool tarIoClose(Tar *t) {
    TarIo *io = &t->io;
    bool ok = true;
    if (io->writing && io->gzip) {
        io->z.avail_in = 0;
        int rc;
        do {
            io->z.next_out = io->zbuf;
            io->z.avail_out = sizeof(io->zbuf);
            rc = deflate(&io->z, Z_FINISH);
            if (!tarWriteFd(io->fd, io->zbuf, sizeof(io->zbuf) - io->z.avail_out)) ok = false;
        } while (rc != Z_STREAM_END);
        deflateEnd(&io->z);
        unsigned char tr[8] = {(unsigned char)io->crc, (unsigned char)(io->crc >> 8), (unsigned char)(io->crc >> 16),
                               (unsigned char)(io->crc >> 24), (unsigned char)io->rawLen, (unsigned char)(io->rawLen >> 8),
                               (unsigned char)(io->rawLen >> 16), (unsigned char)(io->rawLen >> 24)};
        if (!tarWriteFd(io->fd, tr, 8)) ok = false;
    } else if (!io->writing && io->gzip) {
        inflateEnd(&io->z);
    }
    if (io->pipe) {
        int st = pclose(io->pipe);
        io->pipe = NULL;
        if (st != 0 && st != -1) {
            int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
            fprintf(stderr, "tar: Child returned status %d\n", code);
            fputs("tar: Error is not recoverable: exiting now\n", stderr);
            t->status = 2;
            t->fatal = true;
            ok = false;
        }
    }
    if (io->fd > STDERR_FILENO && close(io->fd) != 0) ok = false;
    io->fd = -1;
    return ok;
}

static ssize_t tarRawRead(TarIo *io, void *b, size_t n) {
    if (io->pipe) {
        size_t r = fread(b, 1, n, io->pipe);
        return r == 0 && ferror(io->pipe) ? -1 : (ssize_t)r;
    }
    ssize_t r;
    do r = read(io->fd, b, n);
    while (r < 0 && errno == EINTR);
    return r;
}

/* Opens the archive for reading, compression found by its first bytes. */
static bool tarIoOpenRead(Tar *t, int fd) {
    TarIo *io = &t->io;
    memset(io, 0, sizeof(*io));
    io->fd = fd;
    const char *prog = tarProgram(t->compress, t->compressProg);
    if (prog && fd == STDIN_FILENO) {
        char cmd[4096];
        snprintf(cmd, sizeof(cmd), "%s -d", prog);
        io->pipe = tarPopen(cmd, "r");
        return io->pipe != NULL;
    }
    ssize_t r = 0;
    while (io->npeek < sizeof(io->peek) && (r = tarRawRead(io, io->peek + io->npeek, sizeof(io->peek) - io->npeek)) > 0)
        io->npeek += (size_t)r;
    const unsigned char *p = io->peek;
    size_t n = io->npeek;
    const char *found = NULL;
    if (n >= 2 && p[0] == 0x1f && p[1] == 0x8b) {
        io->gzip = true;
        inflateInit2(&io->z, 15 + 32);
        io->z.next_in = io->peek;
        io->z.avail_in = (uInt)io->npeek;
        io->npeek = 0;
        return true;
    }
    if (n >= 3 && !memcmp(p, "BZh", 3)) found = "bzip2";
    else if (n >= 6 && !memcmp(p, "\xfd" "7zXZ\0", 6)) found = "xz";
    else if (n >= 4 && !memcmp(p, "\x28\xb5\x2f\xfd", 4)) found = "zstd";
    else if (n >= 4 && !memcmp(p, "LZIP", 4)) found = "lzip";
    else if (n >= 2 && p[0] == 0x1f && p[1] == 0x9d) found = "compress";
    else if (n >= 3 && p[0] == 0x5d && p[1] == 0 && p[2] == 0) found = "lzma";
    if (prog && !found) found = prog;
    if (found) {
        if (fd == STDIN_FILENO) {
            tarFatal(t, "Archive is compressed. Use %s option", !strcmp(found, "bzip2") ? "-j" : !strcmp(found, "xz") ? "-J" : "--use-compress-program");
            return false;
        }
        char *q = tarShellQuote(t->archive), cmd[4096];
        snprintf(cmd, sizeof(cmd), "%s -d < %s", found, q);
        free(q);
        close(fd);
        io->fd = -1;
        io->npeek = 0;
        io->pipe = tarPopen(cmd, "r");
        return io->pipe != NULL;
    }
    return true;
}

/* Exactly n bytes unless the archive ends; the count read. */
static size_t tarIoRead(Tar *t, void *b, size_t n) {
    TarIo *io = &t->io;
    unsigned char *out = (unsigned char *)b;
    size_t got = 0;
    while (got < n) {
        if (io->peekPos < io->npeek) {
            size_t k = io->npeek - io->peekPos < n - got ? io->npeek - io->peekPos : n - got;
            memcpy(out + got, io->peek + io->peekPos, k);
            io->peekPos += k;
            got += k;
            continue;
        }
        if (io->eof) break;
        if (io->gzip) {
            if (io->z.avail_in == 0) {
                ssize_t r = tarRawRead(io, io->zbuf, sizeof(io->zbuf));
                if (r <= 0) {
                    io->eof = true;
                    break;
                }
                io->z.next_in = io->zbuf;
                io->z.avail_in = (uInt)r;
            }
            io->z.next_out = out + got;
            io->z.avail_out = (uInt)(n - got);
            int rc = inflate(&io->z, Z_NO_FLUSH);
            got = n - io->z.avail_out;
            if (rc == Z_STREAM_END) {
                /* another gzip member may follow */
                if (io->z.avail_in || true) inflateReset(&io->z);
                if (io->z.avail_in == 0) {
                    unsigned char probe[1];
                    ssize_t r = tarRawRead(io, probe, 1);
                    if (r <= 0) io->eof = true;
                    else {
                        memcpy(io->zbuf, probe, 1);
                        io->z.next_in = io->zbuf;
                        io->z.avail_in = 1;
                    }
                }
            } else if (rc != Z_OK && rc != Z_BUF_ERROR) {
                io->eof = true;
                break;
            }
            continue;
        }
        ssize_t r = tarRawRead(io, out + got, n - got);
        if (r <= 0) {
            io->eof = true;
            break;
        }
        got += (size_t)r;
    }
    io->total += got;
    return got;
}

/* --- Header fields. --- */

static void tarOctal(char *f, size_t len, uintmax_t v) {
    /* octal with a NUL, or base-256 when it does not fit */
    uintmax_t max = 1;
    for (size_t i = 0; i < (len - 1) * 3 && max; i++) max <<= 1;
    if (max && v < max) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%0*jo", (int)(len - 1), v);
        memcpy(f, tmp, len - 1);
        f[len - 1] = '\0';
        return;
    }
    memset(f, 0, len);
    f[0] = (char)0x80;
    for (size_t i = len - 1; i > 0 && v; i--, v >>= 8) f[i] = (char)(v & 0xff);
}

static uintmax_t tarNumber(const char *f, size_t len) {
    const unsigned char *u = (const unsigned char *)f;
    if (u[0] & 0x80) {
        uintmax_t v = u[0] & 0x3f;
        for (size_t i = 1; i < len; i++) v = (v << 8) | u[i];
        return v;
    }
    uintmax_t v = 0;
    size_t i = 0;
    while (i < len && (f[i] == ' ' || f[i] == '\0')) {
        if (f[i] == '\0') return 0;
        i++;
    }
    for (; i < len && f[i] >= '0' && f[i] <= '7'; i++) v = v * 8 + (uintmax_t)(f[i] - '0');
    return v;
}

static unsigned tarChecksum(const TarHeader *h, bool sign) {
    const unsigned char *u = (const unsigned char *)h;
    long sum = 0;
    for (size_t i = 0; i < sizeof(*h); i++) {
        int c = (i >= 148 && i < 156) ? ' ' : (sign ? (signed char)u[i] : u[i]);
        sum += c;
    }
    return (unsigned)sum;
}

static void tarSeal(TarHeader *h) {
    memset(h->chksum, ' ', 8);
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%06o", tarChecksum(h, false));
    memcpy(h->chksum, tmp, 6);
    h->chksum[6] = '\0';
    h->chksum[7] = ' ';
}

static bool tarZeroBlock(const void *b) {
    const unsigned char *u = (const unsigned char *)b;
    for (int i = 0; i < TAR_BLOCK; i++)
        if (u[i]) return false;
    return true;
}

/* --- Listing. --- */

typedef struct {
    char *name, *link;
    char type;
    mode_t mode;
    uintmax_t size, uid, gid, devmajor, devminor;
    struct timespec mtime;
    char uname[64], gname[64];
} TarEntry;

static void tarModeString(const TarEntry *e, char out[11]) {
    char c = '-';
    switch (e->type) {
    case '1': c = 'h'; break;
    case '2': c = 'l'; break;
    case '3': c = 'c'; break;
    case '4': c = 'b'; break;
    case '5': c = 'd'; break;
    case '6': c = 'p'; break;
    case 'V': c = 'V'; break;
    }
    out[0] = c;
    gnuModeString(e->mode, out + 1);
}

static void tarListLong(Tar *t, const TarEntry *e, FILE *f) {
    static __thread int ugswidth = 19;
    char modes[11], user[80], size[64], when[64];
    tarModeString(e, modes);
    char u[64], g[64];
    if (e->uname[0] && !t->numericOwner) snprintf(u, sizeof(u), "%s", e->uname);
    else snprintf(u, sizeof(u), "%ju", e->uid);
    if (e->gname[0] && !t->numericOwner) snprintf(g, sizeof(g), "%s", e->gname);
    else snprintf(g, sizeof(g), "%ju", e->gid);
    snprintf(user, sizeof(user), "%s/%s", u, g);
    if (e->type == '3' || e->type == '4') snprintf(size, sizeof(size), "%ju,%ju", e->devmajor, e->devminor);
    else snprintf(size, sizeof(size), "%ju", e->size);
    struct tm tm;
    time_t tt = e->mtime.tv_sec;
    if (localtime_r(&tt, &tm)) strftime(when, sizeof(when), "%Y-%m-%d %H:%M", &tm);
    else snprintf(when, sizeof(when), "%jd", (intmax_t)tt);
    int pad = (int)(strlen(user) + 1 + strlen(size));
    if (pad > ugswidth) ugswidth = pad;
    fprintf(f, "%s %s %*s %-16s %s", modes, user, ugswidth - pad + (int)strlen(size), size, when, e->name);
    if (e->type == '1') fprintf(f, " link to %s", e->link);
    else if (e->type == '2') fprintf(f, " -> %s", e->link);
    fputc('\n', f);
}

/* --- Names. --- */

/* GNU's leading-"/" and "../" stripping; the member name to use. */
static const char *tarSafeName(Tar *t, const char *name) {
    if (t->absolute) return name;
    const char *p = name;
    if (*p == '/') {
        while (*p == '/') p++;
        if (!t->warnedSlash) {
            fputs("tar: Removing leading `/' from member names\n", stderr);
            t->warnedSlash = true;
        }
    }
    return *p ? p : ".";
}

static bool tarExcluded(const Tar *t, const char *name) {
    for (size_t i = 0; i < t->nexcludes; i++) {
        const char *p = name;
        for (;;) {
            if (fnmatch(t->excludes[i], p, FNM_LEADING_DIR) == 0) return true;
            const char *slash = strchr(p, '/');
            if (!slash) break;
            p = slash + 1;
        }
    }
    return false;
}

static char *tarJoin(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *r = (char *)malloc(la + lb + 2);
    memcpy(r, a, la);
    size_t o = la;
    if (la && a[la - 1] != '/') r[o++] = '/';
    memcpy(r + o, b, lb + 1);
    return r;
}

/* --- Create. --- */

static bool tarPutHeader(Tar *t, const char *name, const char *link, char type, mode_t mode, uintmax_t uid,
                         uintmax_t gid, uintmax_t size, time_t mtime, const char *uname, const char *gname,
                         uintmax_t major, uintmax_t minor, bool isDev);

/* GNU's ././@LongLink entry ahead of a name that does not fit. */
static bool tarLongLink(Tar *t, char type, const char *text) {
    size_t n = strlen(text) + 1;
    if (!tarPutHeader(t, "././@LongLink", NULL, type, 0644, 0, 0, n, 0, "root", "root", 0, 0, false)) return false;
    size_t padded = (n + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK;
    char *b = (char *)calloc(1, padded);
    memcpy(b, text, n);
    bool ok = tarIoWrite(t, b, padded);
    free(b);
    return ok;
}

static bool tarPutHeader(Tar *t, const char *name, const char *link, char type, mode_t mode, uintmax_t uid,
                         uintmax_t gid, uintmax_t size, time_t mtime, const char *uname, const char *gname,
                         uintmax_t major, uintmax_t minor, bool isDev) {
    if (strlen(name) > 100 && strcmp(name, "././@LongLink") && !tarLongLink(t, 'L', name)) return false;
    if (link && strlen(link) > 100 && !tarLongLink(t, 'K', link)) return false;
    TarHeader h;
    memset(&h, 0, sizeof(h));
    memcpy(h.name, name, strlen(name) < 100 ? strlen(name) : 100);
    tarOctal(h.mode, 8, mode & 07777);
    tarOctal(h.uid, 8, uid);
    tarOctal(h.gid, 8, gid);
    tarOctal(h.size, 12, size);
    tarOctal(h.mtime, 12, mtime < 0 ? 0 : (uintmax_t)mtime);
    h.typeflag = type;
    if (link) memcpy(h.linkname, link, strlen(link) < 100 ? strlen(link) : 100);
    memcpy(h.magic, "ustar ", 6);
    memcpy(h.version, " ", 2);
    if (uname) snprintf(h.uname, sizeof(h.uname), "%s", uname);
    if (gname) snprintf(h.gname, sizeof(h.gname), "%s", gname);
    if (isDev) {
        tarOctal(h.devmajor, 8, major);
        tarOctal(h.devminor, 8, minor);
    }
    tarSeal(&h);
    return tarIoWrite(t, &h, sizeof(h));
}

static void tarOwners(Tar *t, const struct stat *st, uintmax_t *uid, uintmax_t *gid, char *u, char *g) {
    *uid = t->ownerSet ? t->ownerUid : st->st_uid;
    *gid = t->groupSet ? t->ownerGid : st->st_gid;
    u[0] = g[0] = '\0';
    if (t->numericOwner) return;
    if (t->ownerSet && t->ownerName) snprintf(u, 32, "%s", t->ownerName);
    else {
        struct passwd *pw = getpwuid((uid_t)*uid);
        if (pw) snprintf(u, 32, "%s", pw->pw_name);
    }
    if (t->groupSet && t->groupName) snprintf(g, 32, "%s", t->groupName);
    else {
        struct group *gr = getgrgid((gid_t)*gid);
        if (gr) snprintf(g, 32, "%s", gr->gr_name);
    }
}

static void tarAdd(Tar *t, const char *fsPath, const char *archName, bool top);

static void tarAddDirEntries(Tar *t, const char *fsPath, const char *archName) {
    DIR *d = opendir(fsPath);
    if (!d) {
        tarErr(t, "%s: Cannot open: %s", fsPath, strerror(errno));
        return;
    }
    struct dirent *e;
    char **names = NULL;
    size_t n = 0;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        names = (char **)realloc(names, (n + 1) * sizeof(char *));
        names[n++] = strdup(e->d_name);
    }
    closedir(d);
    for (size_t i = 0; i < n; i++) {
        char *fp = tarJoin(fsPath, names[i]);
        char *an = tarJoin(archName, names[i]);
        tarAdd(t, fp, an, false);
        free(fp);
        free(an);
        free(names[i]);
    }
    free(names);
}

static void tarAdd(Tar *t, const char *fsPath, const char *archName, bool top) {
    struct stat st;
    if ((t->deref ? stat(fsPath, &st) : lstat(fsPath, &st)) != 0) {
        tarErr(t, "%s: Cannot stat: %s", archName, strerror(errno));
        return;
    }
    const char *name = tarSafeName(t, archName);
    if (tarExcluded(t, name)) return;
    if (t->archiveStOk && st.st_dev == t->archiveSt.st_dev && st.st_ino == t->archiveSt.st_ino) {
        fprintf(stderr, "tar: %s: file is the archive; not dumped\n", archName);
        return;
    }
    if (t->mtimeSet) st.st_mtime = t->mtimeValue.tv_sec;
    if (t->modeSet) st.st_mode = (st.st_mode & ~07777) | gnuModeAdjust(st.st_mode, S_ISDIR(st.st_mode), 0, &t->modeChange, NULL);
    uintmax_t uid, gid;
    char u[33], g[33];
    tarOwners(t, &st, &uid, &gid, u, g);
    TarEntry le;
    memset(&le, 0, sizeof(le));
    le.mode = st.st_mode & 07777;
    le.uid = uid;
    le.gid = gid;
    snprintf(le.uname, sizeof(le.uname), "%s", u);
    snprintf(le.gname, sizeof(le.gname), "%s", g);
    le.mtime.tv_sec = st.st_mtime;
    /* hard links after the first */
    if (!S_ISDIR(st.st_mode) && st.st_nlink > 1) {
        for (size_t i = 0; i < t->nlinks; i++)
            if (t->links[i].dev == st.st_dev && t->links[i].ino == st.st_ino) {
                if (!tarPutHeader(t, name, t->links[i].name, '1', st.st_mode, uid, gid, 0, st.st_mtime, u, g, 0, 0, false))
                    goto werr;
                if (t->verbose) {
                    if (t->verbose > 1) {
                        le.name = (char *)name;
                        le.link = t->links[i].name;
                        le.type = '1';
                        tarListLong(t, &le, t->listOut);
                    } else {
                        fprintf(t->listOut, "%s\n", name);
                    }
                }
                return;
            }
        t->links = (struct TarLinkSeen *)realloc(t->links, (t->nlinks + 1) * sizeof(*t->links));
        t->links[t->nlinks].dev = st.st_dev;
        t->links[t->nlinks].ino = st.st_ino;
        t->links[t->nlinks].name = strdup(name);
        t->nlinks++;
    }
    char *verboseName = NULL;
    if (S_ISDIR(st.st_mode)) {
        size_t n = strlen(name);
        verboseName = (char *)malloc(n + 2);
        memcpy(verboseName, name, n);
        if (n && name[n - 1] != '/') verboseName[n++] = '/';
        verboseName[n] = '\0';
        if (!tarPutHeader(t, verboseName, NULL, '5', st.st_mode, uid, gid, 0, st.st_mtime, u, g, 0, 0, false))
            goto werr;
        le.type = '5';
    } else if (S_ISREG(st.st_mode)) {
        int fd = open(fsPath, O_RDONLY);
        if (fd < 0) {
            tarErr(t, "%s: Cannot open: %s", archName, strerror(errno));
            return;
        }
        if (!tarPutHeader(t, name, NULL, '0', st.st_mode, uid, gid, (uintmax_t)st.st_size, st.st_mtime, u, g, 0, 0, false)) {
            close(fd);
            goto werr;
        }
        unsigned char buf[65536];
        uintmax_t left = (uintmax_t)st.st_size;
        while (left) {
            size_t want = left < sizeof(buf) ? (size_t)left : sizeof(buf);
            ssize_t r = read(fd, buf, want);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) {
                tarErr(t, "%s: File shrank by %ju bytes; padding with zeros", archName, left);
                memset(buf, 0, sizeof(buf));
                while (left) {
                    size_t k = left < sizeof(buf) ? (size_t)left : sizeof(buf);
                    if (!tarIoWrite(t, buf, k)) break;
                    left -= k;
                }
                break;
            }
            if (!tarIoWrite(t, buf, (size_t)r)) {
                close(fd);
                goto werr;
            }
            left -= (uintmax_t)r;
        }
        close(fd);
        size_t pad = (size_t)((TAR_BLOCK - st.st_size % TAR_BLOCK) % TAR_BLOCK);
        if (pad) {
            memset(buf, 0, pad);
            if (!tarIoWrite(t, buf, pad)) goto werr;
        }
        le.type = '0';
        le.size = (uintmax_t)st.st_size;
    } else if (S_ISLNK(st.st_mode)) {
        char target[4096];
        ssize_t n = readlink(fsPath, target, sizeof(target) - 1);
        if (n < 0) {
            tarErr(t, "%s: Cannot readlink: %s", archName, strerror(errno));
            return;
        }
        target[n] = '\0';
        if (!tarPutHeader(t, name, target, '2', st.st_mode, uid, gid, 0, st.st_mtime, u, g, 0, 0, false)) goto werr;
        le.type = '2';
        le.link = target;
        le.name = (char *)name;
        if (t->verbose > 1) tarListLong(t, &le, t->listOut);
        else if (t->verbose) fprintf(t->listOut, "%s\n", name);
        goto removed;
    } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) || S_ISFIFO(st.st_mode)) {
        char type = S_ISCHR(st.st_mode) ? '3' : S_ISBLK(st.st_mode) ? '4' : '6';
        bool dev = type != '6';
        le.devmajor = dev ? major(st.st_rdev) : 0;
        le.devminor = dev ? minor(st.st_rdev) : 0;
        if (!tarPutHeader(t, name, NULL, type, st.st_mode, uid, gid, 0, st.st_mtime, u, g, le.devmajor, le.devminor, dev))
            goto werr;
        le.type = type;
    } else if (S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "tar: %s: socket ignored\n", archName);
        return;
    } else {
        fprintf(stderr, "tar: %s: Unknown file type; file ignored\n", archName);
        return;
    }
    le.name = verboseName ? verboseName : (char *)name;
    if (t->verbose > 1) tarListLong(t, &le, t->listOut);
    else if (t->verbose) fprintf(t->listOut, "%s\n", le.name);
    if (S_ISDIR(st.st_mode) && !t->noRecursion) tarAddDirEntries(t, fsPath, archName);
    free(verboseName);
removed:
    if (t->removeFiles) {
        if ((S_ISDIR(st.st_mode) ? rmdir(fsPath) : unlink(fsPath)) != 0)
            tarErr(t, "%s: Cannot %s: %s", archName, S_ISDIR(st.st_mode) ? "rmdir" : "unlink", strerror(errno));
    }
    (void)top;
    return;
werr:
    free(verboseName);
    tarErr(t, "%s: Cannot write: %s", t->archive, strerror(errno));
}

/* Two zero blocks, then the record filled out. */
static bool tarFinish(Tar *t) {
    unsigned char z[TAR_BLOCK * 2];
    memset(z, 0, sizeof(z));
    if (!tarIoWrite(t, z, sizeof(z))) return false;
    uintmax_t rem = t->io.total % TAR_RECORD;
    if (rem) {
        size_t need = (size_t)(TAR_RECORD - rem);
        unsigned char *pad = (unsigned char *)calloc(1, need);
        bool ok = tarIoWrite(t, pad, need);
        free(pad);
        return ok;
    }
    return true;
}

/* --- Read: headers, with GNU long names and pax records folded in. --- */

typedef struct {
    char *path, *linkpath, *uname, *gname;
    bool haveSize, haveMtime, haveUid, haveGid;
    uintmax_t size, uid, gid;
    struct timespec mtime;
} TarPax;

static void tarPaxFree(TarPax *p) {
    free(p->path);
    free(p->linkpath);
    free(p->uname);
    free(p->gname);
    memset(p, 0, sizeof(*p));
}

static char *tarReadData(Tar *t, uintmax_t size) {
    size_t padded = (size_t)((size + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK);
    char *b = (char *)malloc(padded + 1);
    if (!b) return NULL;
    if (tarIoRead(t, b, padded) != padded) {
        free(b);
        return NULL;
    }
    b[size] = '\0';
    return b;
}

static void tarPaxParse(const char *d, size_t len, TarPax *p) {
    size_t i = 0;
    while (i < len) {
        char *end;
        unsigned long rl = strtoul(d + i, &end, 10);
        if (!rl || *end != ' ' || i + rl > len) break;
        const char *kv = end + 1, *recEnd = d + i + rl - 1;   /* the record's '\n' */
        const char *eq = memchr(kv, '=', (size_t)(recEnd - kv));
        if (eq) {
            size_t kl = (size_t)(eq - kv), vl = (size_t)(recEnd - eq - 1);
            char *val = strndup(eq + 1, vl);
#define PAX_IS(k) (kl == strlen(k) && !strncmp(kv, k, kl))
            if (PAX_IS("path")) free(p->path), p->path = val, val = NULL;
            else if (PAX_IS("linkpath")) free(p->linkpath), p->linkpath = val, val = NULL;
            else if (PAX_IS("uname")) free(p->uname), p->uname = val, val = NULL;
            else if (PAX_IS("gname")) free(p->gname), p->gname = val, val = NULL;
            else if (PAX_IS("size")) p->size = strtoumax(val, NULL, 10), p->haveSize = true;
            else if (PAX_IS("uid")) p->uid = strtoumax(val, NULL, 10), p->haveUid = true;
            else if (PAX_IS("gid")) p->gid = strtoumax(val, NULL, 10), p->haveGid = true;
            else if (PAX_IS("mtime")) {
                char *dot;
                p->mtime.tv_sec = (time_t)strtoimax(val, &dot, 10);
                p->mtime.tv_nsec = 0;
                if (*dot == '.') {
                    long ns = 0;
                    int k = 0;
                    for (dot++; *dot >= '0' && *dot <= '9' && k < 9; dot++, k++) ns = ns * 10 + (*dot - '0');
                    for (; k < 9; k++) ns *= 10;
                    p->mtime.tv_nsec = ns;
                }
                p->haveMtime = true;
            }
#undef PAX_IS
            free(val);
        }
        i += rl;
    }
}

/* The next member; 1 got one, 0 end, -1 not an archive / damaged. */
static int tarNext(Tar *t, TarEntry *e, TarPax *global, bool *firstBlock) {
    TarPax local;
    memset(&local, 0, sizeof(local));
    char *longName = NULL, *longLink = NULL;
    for (;;) {
        TarHeader h;
        size_t got = tarIoRead(t, &h, sizeof(h));
        if (got == 0) {
            if (*firstBlock) return 0;
            tarPaxFree(&local);
            return 0;
        }
        if (got < sizeof(h)) {
            if (*firstBlock) return -1;
            tarErr(t, "Unexpected EOF in archive");
            return -2;
        }
        if (tarZeroBlock(&h)) {
            if (t->ignoreZeros) continue;
            /* a second zero block, or the end */
            TarHeader h2;
            size_t g2 = tarIoRead(t, &h2, sizeof(h2));
            if (g2 == sizeof(h2) && !tarZeroBlock(&h2)) {
                fprintf(stderr, "tar: A lone zero block at %ju\n", (t->io.total - 1024) / TAR_BLOCK + 1);
                memcpy(&h, &h2, sizeof(h));
            } else {
                free(longName);
                free(longLink);
                tarPaxFree(&local);
                return 0;
            }
        }
        unsigned stored = (unsigned)tarNumber(h.chksum, 8);
        if (stored != tarChecksum(&h, false) && stored != tarChecksum(&h, true)) {
            free(longName);
            free(longLink);
            tarPaxFree(&local);
            if (*firstBlock) return -1;
            tarErr(t, "Skipping to next header");
            return -2;
        }
        *firstBlock = false;
        uintmax_t size = tarNumber(h.size, 12);
        if (h.typeflag == 'L' || h.typeflag == 'K') {
            char *d = tarReadData(t, size);
            if (!d) return -2;
            if (h.typeflag == 'L') free(longName), longName = d;
            else free(longLink), longLink = d;
            continue;
        }
        if (h.typeflag == 'x' || h.typeflag == 'g') {
            char *d = tarReadData(t, size);
            if (!d) return -2;
            tarPaxParse(d, (size_t)size, h.typeflag == 'g' ? global : &local);
            free(d);
            continue;
        }
        memset(e, 0, sizeof(*e));
        char name[257];
        if (!memcmp(h.magic, "ustar\0", 6) && h.prefix[0])
            snprintf(name, sizeof(name), "%.155s/%.100s", h.prefix, h.name);
        else
            snprintf(name, sizeof(name), "%.100s", h.name);
        e->name = strdup(local.path ? local.path : longName ? longName : global->path ? global->path : name);
        char link[101];
        snprintf(link, sizeof(link), "%.100s", h.linkname);
        e->link = strdup(local.linkpath ? local.linkpath : longLink ? longLink : link);
        e->type = h.typeflag ? h.typeflag : '0';
        if (e->type == '7') e->type = '0';
        e->mode = (mode_t)tarNumber(h.mode, 8) & 07777;
        e->size = local.haveSize ? local.size : size;
        e->uid = local.haveUid ? local.uid : tarNumber(h.uid, 8);
        e->gid = local.haveGid ? local.gid : tarNumber(h.gid, 8);
        e->mtime.tv_sec = (time_t)tarNumber(h.mtime, 12);
        if (local.haveMtime) e->mtime = local.mtime;
        snprintf(e->uname, sizeof(e->uname), "%s", local.uname ? local.uname : global->uname ? global->uname : h.uname);
        snprintf(e->gname, sizeof(e->gname), "%s", local.gname ? local.gname : global->gname ? global->gname : h.gname);
        e->devmajor = tarNumber(h.devmajor, 8);
        e->devminor = tarNumber(h.devminor, 8);
        /* old archives mark directories with a trailing slash only */
        size_t nl = strlen(e->name);
        if (e->type == '0' && nl && e->name[nl - 1] == '/') e->type = '5';
        free(longName);
        free(longLink);
        tarPaxFree(&local);
        return 1;
    }
}

static bool tarSkipData(Tar *t, uintmax_t size) {
    unsigned char buf[TAR_BLOCK * 16];
    uintmax_t padded = (size + TAR_BLOCK - 1) / TAR_BLOCK * TAR_BLOCK;
    while (padded) {
        size_t k = padded < sizeof(buf) ? (size_t)padded : sizeof(buf);
        if (tarIoRead(t, buf, k) != k) return false;
        padded -= k;
    }
    return true;
}

static bool tarHasData(char type) {
    return type == '0' || type == 'S';
}

static void tarMkParents(const char *path) {
    char *p = strdup(path);
    for (char *s = p + 1; *s; s++) {
        if (*s != '/') continue;
        *s = '\0';
        mkdir(p, 0777);
        *s = '/';
    }
    free(p);
}

static void tarApplyOwner(Tar *t, const char *path, const TarEntry *e, bool link) {
    bool same = t->sameOwner < 0 ? geteuid() == 0 : t->sameOwner;
    if (!same) return;
    uid_t uid = (uid_t)e->uid;
    gid_t gid = (gid_t)e->gid;
    if (!t->numericOwner) {
        struct passwd *pw = e->uname[0] ? getpwnam(e->uname) : NULL;
        struct group *gr = e->gname[0] ? getgrnam(e->gname) : NULL;
        if (pw) uid = pw->pw_uid;
        if (gr) gid = gr->gr_gid;
    }
    if ((link ? lchown(path, uid, gid) : chown(path, uid, gid)) != 0 && geteuid() == 0)
        tarErr(t, "%s: Cannot change ownership to uid %ju, gid %ju: %s", path, (uintmax_t)uid, (uintmax_t)gid, strerror(errno));
}

static mode_t tarModeFor(const Tar *t, mode_t m) {
    bool same = t->samePerms < 0 ? geteuid() == 0 : t->samePerms;
    return same ? m : m & ~t->umaskValue;
}

static void tarSetTimes(Tar *t, const char *path, const TarEntry *e, bool link) {
    if (t->noMtime) return;
    struct timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = UTIME_NOW;
    ts[1] = e->mtime;
    if (utimensat(AT_FDCWD, path, ts, link ? AT_SYMLINK_NOFOLLOW : 0) != 0 && !link)
        tarErr(t, "%s: Cannot utime: %s", path, strerror(errno));
}

/* Extract one member (its data, if any, not yet read). */
static bool tarExtractOne(Tar *t, const TarEntry *e, const char *path) {
    struct stat st;
    if (t->toStdout) {
        if (!tarHasData(e->type)) return true;
        unsigned char buf[65536];
        uintmax_t left = e->size;
        while (left) {
            size_t k = left < sizeof(buf) ? (size_t)left : sizeof(buf);
            if (tarIoRead(t, buf, k) != k) return false;
            fwrite(buf, 1, k, stdout);
            left -= k;
        }
        size_t pad = (size_t)((TAR_BLOCK - e->size % TAR_BLOCK) % TAR_BLOCK);
        return !pad || tarIoRead(t, buf, pad) == pad;
    }
    tarMkParents(path);
    bool exists = lstat(path, &st) == 0;
    if (exists && e->type != '5') {
        if (t->skipOld) return tarSkipData(t, tarHasData(e->type) ? e->size : 0);
        if (t->keepOld) {
            tarErr(t, "%s: Cannot open: File exists", path);
            return tarSkipData(t, tarHasData(e->type) ? e->size : 0);
        }
        if (S_ISDIR(st.st_mode) ? rmdir(path) != 0 && errno != ENOTEMPTY && errno != EEXIST : unlink(path) != 0) {}
    }
    switch (e->type) {
    case '5': {
        if (!exists || !S_ISDIR(st.st_mode)) {
            if (mkdir(path, 0700) != 0 && errno != EEXIST) {
                tarErr(t, "%s: Cannot mkdir: %s", path, strerror(errno));
                return true;
            }
        }
        t->delayed = (struct TarDelayed *)realloc(t->delayed, (t->ndelayed + 1) * sizeof(*t->delayed));
        struct TarDelayed *dd = &t->delayed[t->ndelayed++];
        dd->path = strdup(path);
        dd->mode = tarModeFor(t, e->mode);
        dd->mtime = e->mtime;
        dd->uid = (uid_t)e->uid;
        dd->gid = (gid_t)e->gid;
        dd->owner = true;
        tarApplyOwner(t, path, e, false);
        return true;
    }
    case '2':
        if (symlink(e->link, path) != 0) {
            char q[4200];
            tarErr(t, "%s: Cannot create symlink to %s: %s", path, gnuQuote(e->link, q, sizeof(q)), strerror(errno));
            return true;
        }
        tarApplyOwner(t, path, e, true);
        tarSetTimes(t, path, e, true);
        return true;
    case '1': {
        const char *target = tarSafeName(t, e->link);
        if (link(target, path) != 0) {
            char q[4200];
            tarErr(t, "%s: Cannot hard link to %s: %s", path, gnuQuote(target, q, sizeof(q)), strerror(errno));
        }
        return true;
    }
    case '3': case '4': case '6': {
        mode_t type = e->type == '3' ? S_IFCHR : e->type == '4' ? S_IFBLK : S_IFIFO;
        int rc = e->type == '6' ? mkfifo(path, tarModeFor(t, e->mode))
                                : mknod(path, type | tarModeFor(t, e->mode), makedev((unsigned)e->devmajor, (unsigned)e->devminor));
        if (rc != 0) {
            tarErr(t, "%s: Cannot mknod: %s", path, strerror(errno));
            return true;
        }
        tarApplyOwner(t, path, e, false);
        chmod(path, tarModeFor(t, e->mode));
        tarSetTimes(t, path, e, false);
        return true;
    }
    default: {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            tarErr(t, "%s: Cannot open: %s", path, strerror(errno));
            return tarSkipData(t, e->size);
        }
        unsigned char buf[65536];
        uintmax_t left = e->size;
        bool ok = true;
        while (left) {
            size_t k = left < sizeof(buf) ? (size_t)left : sizeof(buf);
            if (tarIoRead(t, buf, k) != k) {
                ok = false;
                break;
            }
            if (!tarWriteFd(fd, buf, k)) {
                tarErr(t, "%s: Cannot write: %s", path, strerror(errno));
                break;
            }
            left -= k;
        }
        if (ok && e->size % TAR_BLOCK) ok = tarIoRead(t, buf, TAR_BLOCK - e->size % TAR_BLOCK) == TAR_BLOCK - e->size % TAR_BLOCK;
        tarApplyOwner(t, path, e, false);
        fchmod(fd, tarModeFor(t, e->mode));
        close(fd);
        tarSetTimes(t, path, e, false);
        if (!ok) {
            tarErr(t, "Unexpected EOF in archive");
            return false;
        }
        return true;
    }
    }
}

/* --- Driving. --- */

typedef struct {
    char *pat;
    bool found;
} TarName;

static bool tarMatches(Tar *t, TarName *names, size_t n, const char *name) {
    if (!n) return true;
    bool any = false;
    for (size_t i = 0; i < n; i++) {
        const char *p = names[i].pat;
        size_t pl = strlen(p);
        bool m;
        if (t->wildcards) m = fnmatch(p, name, FNM_LEADING_DIR) == 0;
        else m = !strcmp(name, p) || (!strncmp(name, p, pl) && (name[pl] == '/' || (pl && p[pl - 1] == '/')));
        if (m) {
            names[i].found = true;
            any = true;
        }
    }
    return any;
}

/* --strip-components and the ".." refusal; NULL to skip. */
static char *tarMemberPath(Tar *t, const char *raw) {
    const char *name = tarSafeName(t, raw);
    for (intmax_t k = 0; k < t->strip; k++) {
        const char *slash = strchr(name, '/');
        if (!slash) return NULL;
        name = slash + 1;
        while (*name == '/') name++;
    }
    if (!*name) return NULL;
    for (const char *p = name; *p;) {
        const char *s = strchr(p, '/');
        size_t len = s ? (size_t)(s - p) : strlen(p);
        if (len == 2 && p[0] == '.' && p[1] == '.' && !t->absolute) {
            tarErr(t, "%s: Member name contains '..'", raw);
            return NULL;
        }
        if (!s) break;
        p = s + 1;
    }
    return strdup(name);
}

static int tarReadArchive(Tar *t, TarName *names, size_t nnames, const char *base) {
    int fd = STDIN_FILENO;
    if (!strcmp(t->archive, "-") && isatty(STDIN_FILENO)) {
        tarFatal(t, "Refusing to read archive contents from terminal (missing -f option?)");
        return 2;
    }
    if (strcmp(t->archive, "-")) {
        fd = open(t->archive, O_RDONLY);
        if (fd < 0) {
            tarFatal(t, "%s: Cannot open: %s", t->archive, strerror(errno));
            return 2;
        }
    }
    if (!tarIoOpenRead(t, fd)) return 2;
    TarPax global;
    memset(&global, 0, sizeof(global));
    bool first = true;
    TarEntry e;
    int r;
    while ((r = tarNext(t, &e, &global, &first)) == 1) {
        char *path = tarMemberPath(t, e.name);
        bool selected = path && !tarExcluded(t, path) && tarMatches(t, names, nnames, path);
        if (!selected) {
            free(path);
            if (!tarSkipData(t, tarHasData(e.type) ? e.size : 0)) break;
            free(e.name);
            free(e.link);
            continue;
        }
        char *shown = e.name;
        e.name = path;
        if (t->op == 't' || t->verbose) {
            if (t->op == 't' ? t->verbose : t->verbose > 1) tarListLong(t, &e, t->listOut);
            else fprintf(t->listOut, "%s\n", path);
        }
        if (t->op == 't') {
            if (!tarSkipData(t, tarHasData(e.type) ? e.size : 0)) {
                tarErr(t, "Unexpected EOF in archive");
                r = -2;
            }
        } else {
            char *fs = base ? tarJoin(base, path) : strdup(path);
            TarEntry x = e;
            char *linkFs = NULL;
            if (e.type == '1') {
                char *lp = tarMemberPath(t, e.link);
                linkFs = lp ? (base ? tarJoin(base, lp) : strdup(lp)) : strdup(e.link);
                free(lp);
                x.link = linkFs;
            }
            if (!tarExtractOne(t, &x, fs)) r = -2;
            free(fs);
            free(linkFs);
        }
        free(shown);
        free(path);
        free(e.link);
        if (r == -2) break;
    }
    tarPaxFree(&global);
    if (r == -1) {
        tarErr(t, "This does not look like a tar archive");
    }
    tarIoClose(t);
    /* directories last, deepest first */
    for (size_t i = t->ndelayed; i-- > 0;) {
        struct TarDelayed *d = &t->delayed[i];
        chmod(d->path, d->mode);
        if (!t->noMtime) {
            struct timespec ts[2] = {{0, UTIME_NOW}, d->mtime};
            utimensat(AT_FDCWD, d->path, ts, 0);
        }
        free(d->path);
    }
    t->ndelayed = 0;
    for (size_t i = 0; i < nnames; i++)
        if (!names[i].found) tarErr(t, "%s: Not found in archive", names[i].pat);
    return t->status;
}

typedef struct {
    bool chdir;
    char *value;
} TarItem;

/* -r / -u: the offset of the end-of-archive blocks, and for -u each
 * member's latest mtime. */
static int tarAppend(Tar *t, TarItem *items, size_t nitems) {
    if (t->compress || !strcmp(t->archive, "-")) {
        tarFatal(t, "Cannot update compressed archives");
        return 2;
    }
    int fd = open(t->archive, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        tarFatal(t, "%s: Cannot open: %s", t->archive, strerror(errno));
        return 2;
    }
    memset(&t->io, 0, sizeof(t->io));
    t->io.fd = fd;
    TarPax global;
    memset(&global, 0, sizeof(global));
    bool first = true;
    TarEntry e;
    off_t end = 0;
    char **seenNames = NULL;
    time_t *seenTimes = NULL;
    size_t nseen = 0;
    for (;;) {
        uintmax_t before = t->io.total;
        int r = tarNext(t, &e, &global, &first);
        if (r == 0) {
            end = (off_t)before;
            break;
        }
        if (r < 0) {
            tarFatal(t, "This does not look like a tar archive");
            close(fd);
            tarPaxFree(&global);
            return 2;
        }
        if (t->op == 'u') {
            seenNames = (char **)realloc(seenNames, (nseen + 1) * sizeof(char *));
            seenTimes = (time_t *)realloc(seenTimes, (nseen + 1) * sizeof(time_t));
            seenNames[nseen] = strdup(e.name);
            seenTimes[nseen++] = e.mtime.tv_sec;
        }
        tarSkipData(t, tarHasData(e.type) ? e.size : 0);
        end = (off_t)t->io.total;
        free(e.name);
        free(e.link);
    }
    tarPaxFree(&global);
    if (lseek(fd, end, SEEK_SET) < 0) {
        tarFatal(t, "%s: Cannot seek: %s", t->archive, strerror(errno));
        close(fd);
        return 2;
    }
    memset(&t->io, 0, sizeof(t->io));
    t->io.fd = fd;
    t->io.writing = true;
    t->io.total = (uintmax_t)end;
    fstat(fd, &t->archiveSt);
    t->archiveStOk = true;
    char *base = NULL;
    for (size_t i = 0; i < nitems; i++) {
        if (items[i].chdir) {
            char *nb = base && items[i].value[0] != '/' ? tarJoin(base, items[i].value) : strdup(items[i].value);
            free(base);
            base = nb;
            continue;
        }
        if (t->op == 'u') {
            struct stat st;
            char *fp = base ? tarJoin(base, items[i].value) : strdup(items[i].value);
            bool newer = true;
            if (lstat(fp, &st) == 0)
                for (size_t k = 0; k < nseen; k++)
                    if (!strcmp(seenNames[k], tarSafeName(t, items[i].value)) && seenTimes[k] >= st.st_mtime) newer = false;
            if (newer) tarAdd(t, fp, items[i].value, true);
            free(fp);
            continue;
        }
        char *fp = base ? tarJoin(base, items[i].value) : strdup(items[i].value);
        tarAdd(t, fp, items[i].value, true);
        free(fp);
    }
    free(base);
    if (!tarFinish(t)) tarErr(t, "%s: Cannot write: %s", t->archive, strerror(errno));
    off_t now = lseek(fd, 0, SEEK_CUR);
    if (now >= 0 && ftruncate(fd, now) != 0) {}
    close(fd);
    for (size_t k = 0; k < nseen; k++) free(seenNames[k]);
    free(seenNames);
    free(seenTimes);
    return t->status;
}

static int tarCreate(Tar *t, TarItem *items, size_t nitems) {
    int fd = STDOUT_FILENO;
    if (!nitems) {
        tarFatal(t, "Cowardly refusing to create an empty archive");
        fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
        return 2;
    }
    if (strcmp(t->archive, "-")) {
        fd = open(t->archive, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            tarFatal(t, "%s: Cannot open: %s", t->archive, strerror(errno));
            return 2;
        }
        if (fstat(fd, &t->archiveSt) == 0) t->archiveStOk = true;
    } else if (isatty(STDOUT_FILENO)) {
        tarFatal(t, "Refusing to write archive contents to terminal (missing -f option?)");
        return 2;
    }
    if (!tarIoOpenWrite(t, fd)) {
        tarFatal(t, "%s: Cannot open: %s", t->archive, strerror(errno));
        return 2;
    }
    char *base = NULL;
    for (size_t i = 0; i < nitems; i++) {
        if (items[i].chdir) {
            char *nb = base && items[i].value[0] != '/' ? tarJoin(base, items[i].value) : strdup(items[i].value);
            free(base);
            base = nb;
            struct stat st;
            if (stat(base, &st) != 0) {
                tarFatal(t, "%s: Cannot open: %s", items[i].value, strerror(errno));
                free(base);
                tarIoClose(t);
                return 2;
            }
            continue;
        }
        char *fp = base ? tarJoin(base, items[i].value) : strdup(items[i].value);
        tarAdd(t, fp, items[i].value, true);
        free(fp);
    }
    free(base);
    bool ok = tarFinish(t);
    if (!tarIoClose(t) || !ok) {
        if (t->status != 2) tarErr(t, "%s: Cannot write: %s", t->archive, strerror(errno));
    }
    if (t->totals) {
        fprintf(stderr, "Total bytes written: %ju\n", t->io.total);
    }
    return t->status;
}

/* --- Options. --- */

enum {
    TO_SKIP_OLD = 256, TO_OVERWRITE, TO_NO_SAME_PERMS, TO_SAME_OWNER, TO_NO_SAME_OWNER, TO_STRIP, TO_EXCLUDE,
    TO_NULL, TO_NO_NULL, TO_NO_RECURSION, TO_RECURSION, TO_OWNER, TO_GROUP, TO_NUMERIC_OWNER, TO_MODE, TO_MTIME,
    TO_REMOVE_FILES, TO_WILDCARDS, TO_NO_WILDCARDS, TO_TOTALS, TO_FORMAT, TO_LZIP, TO_LZMA, TO_LZOP, TO_ZSTD,
    TO_IGNORED, TO_IGNORED_ARG, TO_HELP, TO_VERSION, TO_SORT, TO_ONE_FS,
};

static const GnuLongOpt tarLongs[] = {
    {"create", GNU_NO_ARG, 'c'}, {"extract", GNU_NO_ARG, 'x'}, {"get", GNU_NO_ARG, 'x'},
    {"list", GNU_NO_ARG, 't'}, {"append", GNU_NO_ARG, 'r'}, {"update", GNU_NO_ARG, 'u'},
    {"file", GNU_REQ_ARG, 'f'}, {"directory", GNU_REQ_ARG, 'C'}, {"verbose", GNU_NO_ARG, 'v'},
    {"gzip", GNU_NO_ARG, 'z'}, {"gunzip", GNU_NO_ARG, 'z'}, {"ungzip", GNU_NO_ARG, 'z'},
    {"bzip2", GNU_NO_ARG, 'j'}, {"xz", GNU_NO_ARG, 'J'}, {"compress", GNU_NO_ARG, 'Z'},
    {"uncompress", GNU_NO_ARG, 'Z'}, {"lzip", GNU_NO_ARG, TO_LZIP}, {"lzma", GNU_NO_ARG, TO_LZMA},
    {"lzop", GNU_NO_ARG, TO_LZOP}, {"zstd", GNU_NO_ARG, TO_ZSTD}, {"auto-compress", GNU_NO_ARG, 'a'},
    {"use-compress-program", GNU_REQ_ARG, 'I'}, {"to-stdout", GNU_NO_ARG, 'O'},
    {"keep-old-files", GNU_NO_ARG, 'k'}, {"skip-old-files", GNU_NO_ARG, TO_SKIP_OLD},
    {"overwrite", GNU_NO_ARG, TO_OVERWRITE}, {"unlink-first", GNU_NO_ARG, 'U'},
    {"preserve-permissions", GNU_NO_ARG, 'p'}, {"same-permissions", GNU_NO_ARG, 'p'},
    {"no-same-permissions", GNU_NO_ARG, TO_NO_SAME_PERMS}, {"same-owner", GNU_NO_ARG, TO_SAME_OWNER},
    {"no-same-owner", GNU_NO_ARG, TO_NO_SAME_OWNER}, {"touch", GNU_NO_ARG, 'm'},
    {"dereference", GNU_NO_ARG, 'h'}, {"absolute-names", GNU_NO_ARG, 'P'},
    {"strip-components", GNU_REQ_ARG, TO_STRIP}, {"exclude", GNU_REQ_ARG, TO_EXCLUDE},
    {"exclude-from", GNU_REQ_ARG, 'X'}, {"files-from", GNU_REQ_ARG, 'T'}, {"null", GNU_NO_ARG, TO_NULL},
    {"no-null", GNU_NO_ARG, TO_NO_NULL}, {"no-recursion", GNU_NO_ARG, TO_NO_RECURSION},
    {"recursion", GNU_NO_ARG, TO_RECURSION}, {"owner", GNU_REQ_ARG, TO_OWNER}, {"group", GNU_REQ_ARG, TO_GROUP},
    {"numeric-owner", GNU_NO_ARG, TO_NUMERIC_OWNER}, {"mode", GNU_REQ_ARG, TO_MODE},
    {"mtime", GNU_REQ_ARG, TO_MTIME}, {"remove-files", GNU_NO_ARG, TO_REMOVE_FILES},
    {"wildcards", GNU_NO_ARG, TO_WILDCARDS}, {"no-wildcards", GNU_NO_ARG, TO_NO_WILDCARDS},
    {"ignore-zeros", GNU_NO_ARG, 'i'}, {"totals", GNU_NO_ARG, TO_TOTALS}, {"format", GNU_REQ_ARG, 'H'},
    {"blocking-factor", GNU_REQ_ARG, 'b'}, {"sort", GNU_REQ_ARG, TO_SORT},
    {"one-file-system", GNU_NO_ARG, TO_ONE_FS}, {"checkpoint", GNU_OPT_ARG, TO_IGNORED_ARG},
    {"warning", GNU_REQ_ARG, TO_IGNORED_ARG}, {"no-xattrs", GNU_NO_ARG, TO_IGNORED},
    {"xattrs", GNU_NO_ARG, TO_IGNORED}, {"no-acls", GNU_NO_ARG, TO_IGNORED}, {"acls", GNU_NO_ARG, TO_IGNORED},
    {"no-selinux", GNU_NO_ARG, TO_IGNORED}, {"selinux", GNU_NO_ARG, TO_IGNORED},
    {"delay-directory-restore", GNU_NO_ARG, TO_IGNORED}, {"no-overwrite-dir", GNU_NO_ARG, TO_IGNORED},
    {"anchored", GNU_NO_ARG, TO_IGNORED}, {"no-anchored", GNU_NO_ARG, TO_IGNORED},
    {"help", GNU_NO_ARG, TO_HELP}, {"version", GNU_NO_ARG, TO_VERSION},
};

static int tarCompressFor(const char *name) {
    static const struct { const char *suffix; int c; } m[] = {
        {".gz", 'z'}, {".tgz", 'z'}, {".taz", 'Z'}, {".Z", 'Z'}, {".bz2", 'j'}, {".tbz", 'j'}, {".tbz2", 'j'},
        {".tb2", 'j'}, {".xz", 'J'}, {".txz", 'J'}, {".lz", 'L'}, {".lzma", 'M'}, {".tlz", 'M'}, {".lzo", 'O'},
        {".zst", 'S'}, {".tzst", 'S'},
    };
    size_t n = strlen(name);
    for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        size_t l = strlen(m[i].suffix);
        if (n > l && !strcmp(name + n - l, m[i].suffix)) return m[i].c;
    }
    return 0;
}

static void tarAddItem(TarItem **items, size_t *n, bool chdir, const char *v) {
    *items = (TarItem *)realloc(*items, (*n + 1) * sizeof(TarItem));
    (*items)[*n].chdir = chdir;
    (*items)[*n].value = strdup(v);
    (*n)++;
}

static bool tarFilesFrom(Tar *t, const char *file, TarItem **items, size_t *n) {
    FILE *f = strcmp(file, "-") ? fopen(file, "r") : stdin;
    if (!f) {
        tarFatal(t, "%s: Cannot open: %s", file, strerror(errno));
        return false;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getdelim(&line, &cap, t->nullNames ? '\0' : '\n', f)) > 0) {
        if (line[len - 1] == (t->nullNames ? '\0' : '\n')) line[--len] = '\0';
        if (!len) continue;
        if (!t->nullNames && !strncmp(line, "-C", 2)) {
            const char *d = line + 2;
            while (*d == ' ') d++;
            tarAddItem(items, n, true, d);
            continue;
        }
        tarAddItem(items, n, false, line);
    }
    free(line);
    if (f != stdin) fclose(f);
    return true;
}

int smallclueTarCommand(int argc, char **argv) {
    Tar t;
    memset(&t, 0, sizeof(t));
    t.archive = getenv("TAPE");
    if (!t.archive || !*t.archive) t.archive = "-";
    t.sameOwner = t.samePerms = -1;
    t.listOut = stdout;
    t.umaskValue = umask(0);
    umask(t.umaskValue);
    /* the old style: "tar cvzf a.tgz dir" */
    char **av = argv;
    int ac = argc;
    char **built = NULL, **allocated = NULL;
    int nallocated = 0;
    if (argc > 1 && argv[1][0] && argv[1][0] != '-') {
        built = (char **)calloc((size_t)argc * 2 + 2, sizeof(char *));
        allocated = (char **)calloc(strlen(argv[1]) + 1, sizeof(char *));
        int n = 0, next = 2;
        built[n++] = argv[0];
        for (const char *p = argv[1]; *p; p++) {
            char *opt = (char *)malloc(3);
            opt[0] = '-';
            opt[1] = *p;
            opt[2] = '\0';
            built[n++] = opt;
            allocated[nallocated++] = opt;
            if (strchr("fbCTXIgKLNV", *p)) {
                if (next >= argc) {
                    fprintf(stderr, "tar: option requires an argument -- '%c'\n", *p);
                    fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
                    for (int i = 0; i < nallocated; i++) free(allocated[i]);
                    free(allocated);
                    free(built);
                    return 2;
                }
                built[n++] = argv[next++];
            }
        }
        for (int i = next; i < argc; i++) built[n++] = argv[i];
        av = built;
        ac = n;
    }
    GnuGetopt g;
    gnuGetoptInit(&g, ac, av, "tar", "AcdtrxuzjJZaf:C:vOkUpmhPT:X:I:ib:H:Ww", tarLongs, sizeof(tarLongs) / sizeof(tarLongs[0]));
    g.inOrder = true;
    TarItem *items = NULL;
    size_t nitems = 0;
    int c, status = 2;
    char q[512];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 1: tarAddItem(&items, &nitems, false, g.arg); break;
        case 'c': case 'x': case 't': case 'r': case 'u': case 'A': case 'd':
            if (t.op && t.op != c) {
                fputs("tar: You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option\n", stderr);
                fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
                goto done;
            }
            t.op = c;
            break;
        case 'f': t.archive = g.arg; break;
        case 'C': tarAddItem(&items, &nitems, true, g.arg); break;
        case 'v': t.verbose++; break;
        case 'z': case 'j': case 'J': case 'Z': t.compress = c; break;
        case TO_LZIP: t.compress = 'L'; break;
        case TO_LZMA: t.compress = 'M'; break;
        case TO_LZOP: t.compress = 'O'; break;
        case TO_ZSTD: t.compress = 'S'; break;
        case 'I': t.compress = 'I'; t.compressProg = g.arg; break;
        case 'a': t.autoCompress = true; break;
        case 'O': t.toStdout = true; break;
        case 'k': t.keepOld = true; break;
        case TO_SKIP_OLD: t.skipOld = true; break;
        case TO_OVERWRITE: case 'U': t.keepOld = t.skipOld = false; break;
        case 'p': t.samePerms = 1; break;
        case TO_NO_SAME_PERMS: t.samePerms = 0; break;
        case TO_SAME_OWNER: t.sameOwner = 1; break;
        case TO_NO_SAME_OWNER: t.sameOwner = 0; break;
        case 'm': t.noMtime = true; break;
        case 'h': t.deref = true; break;
        case 'P': t.absolute = true; break;
        case TO_STRIP: {
            char *end;
            t.strip = strtoimax(g.arg, &end, 10);
            if (end == g.arg || *end || t.strip < 0) {
                fprintf(stderr, "tar: %s: Invalid number of elements\n", g.arg);
                fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
                goto done;
            }
            break;
        }
        case TO_EXCLUDE:
            t.excludes = (char **)realloc(t.excludes, (t.nexcludes + 1) * sizeof(char *));
            t.excludes[t.nexcludes++] = strdup(g.arg);
            break;
        case 'X': {
            FILE *f = fopen(g.arg, "r");
            if (!f) {
                tarFatal(&t, "%s: Cannot open: %s", g.arg, strerror(errno));
                goto done;
            }
            char line[4096];
            while (fgets(line, sizeof(line), f)) {
                size_t n = strlen(line);
                if (n && line[n - 1] == '\n') line[--n] = '\0';
                if (!n) continue;
                t.excludes = (char **)realloc(t.excludes, (t.nexcludes + 1) * sizeof(char *));
                t.excludes[t.nexcludes++] = strdup(line);
            }
            fclose(f);
            break;
        }
        case 'T': if (!tarFilesFrom(&t, g.arg, &items, &nitems)) goto done; break;
        case TO_NULL: t.nullNames = true; break;
        case TO_NO_NULL: t.nullNames = false; break;
        case TO_NO_RECURSION: t.noRecursion = true; break;
        case TO_RECURSION: t.noRecursion = false; break;
        case TO_OWNER: case TO_GROUP: {
            const char *v = g.arg, *colon = strchr(v, ':');
            char nm[256];
            snprintf(nm, sizeof(nm), "%.*s", colon ? (int)(colon - v) : (int)strlen(v), v);
            uintmax_t id = 0;
            bool numeric = colon || (nm[0] && strspn(nm, "0123456789") == strlen(nm));
            if (colon) id = strtoumax(colon + 1, NULL, 10);
            else if (numeric) id = strtoumax(nm, NULL, 10);
            if (c == TO_OWNER) {
                struct passwd *pw = !numeric || colon ? getpwnam(nm) : NULL;
                if (!colon && !numeric) {
                    if (!pw) {
                        fprintf(stderr, "tar: %s: Invalid owner\n", nm);
                        goto done;
                    }
                    id = pw->pw_uid;
                }
                t.ownerUid = (uid_t)id;
                t.ownerName = !numeric || colon ? strdup(nm) : NULL;
                t.ownerSet = true;
            } else {
                struct group *gr = !numeric || colon ? getgrnam(nm) : NULL;
                if (!colon && !numeric) {
                    if (!gr) {
                        fprintf(stderr, "tar: %s: Invalid group\n", nm);
                        goto done;
                    }
                    id = gr->gr_gid;
                }
                t.ownerGid = (gid_t)id;
                t.groupName = !numeric || colon ? strdup(nm) : NULL;
                t.groupSet = true;
            }
            break;
        }
        case TO_NUMERIC_OWNER: t.numericOwner = true; break;
        case TO_MODE:
            if (!gnuModeCompile(g.arg, &t.modeChange)) {
                fprintf(stderr, "tar: Invalid mode given on option\n");
                goto done;
            }
            t.modeSet = true;
            break;
        case TO_MTIME: {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            struct stat st;
            if (g.arg[0] == '/' || g.arg[0] == '.' ? stat(g.arg, &st) == 0 : false) {
                t.mtimeValue.tv_sec = st.st_mtime;
            } else if (!smallclueParseDatetime(g.arg, now, &t.mtimeValue)) {
                fprintf(stderr, "tar: Invalid date format %s\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto done;
            }
            t.mtimeSet = true;
            break;
        }
        case TO_REMOVE_FILES: t.removeFiles = true; break;
        case TO_WILDCARDS: t.wildcards = true; break;
        case TO_NO_WILDCARDS: t.wildcards = false; break;
        case 'i': t.ignoreZeros = true; break;
        case TO_TOTALS: t.totals = true; break;
        case 'H':
            if (strcmp(g.arg, "gnu") && strcmp(g.arg, "oldgnu") && strcmp(g.arg, "ustar") && strcmp(g.arg, "posix") &&
                strcmp(g.arg, "pax") && strcmp(g.arg, "v7")) {
                fprintf(stderr, "tar: %s: Invalid archive format\n", gnuQuoteLocale(g.arg, q, sizeof(q)));
                goto done;
            }
            break;
        case 'b': case TO_SORT: case TO_ONE_FS: case TO_IGNORED: case TO_IGNORED_ARG: case 'W': case 'w': break;
        case TO_HELP:
            puts("Usage: tar [OPTION...] [FILE]...\n"
                 "GNU 'tar' saves many files together into a single tape or disk archive, and can\n"
                 "restore individual files from the archive.\n\n"
                 "Examples:\n"
                 "  tar -cf archive.tar foo bar  # Create archive.tar from files foo and bar.\n"
                 "  tar -tvf archive.tar         # List all files in archive.tar verbosely.\n"
                 "  tar -xf archive.tar          # Extract all files from archive.tar.");
            status = 0;
            goto done;
        case TO_VERSION: puts("tar (GNU tar) 1.35 (SmallCLUE)"); status = 0; goto done;
        default:
            fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
            goto done;
        }
    }
    if (!t.op) {
        fputs("tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\n", stderr);
        fputs("Try 'tar --help' or 'tar --usage' for more information.\n", stderr);
        goto done;
    }
    if (t.op == 'A' || t.op == 'd') {
        tarFatal(&t, "-%c is not supported here", t.op);
        goto done;
    }
    if (t.autoCompress && (t.op == 'c') && !t.compress) t.compress = tarCompressFor(t.archive);
    if (!strcmp(t.archive, "-") && t.op == 'c') t.listOut = stderr;
    if (t.toStdout) t.listOut = stderr;
    if (t.op == 'c') {
        status = tarCreate(&t, items, nitems);
    } else if (t.op == 'r' || t.op == 'u') {
        status = tarAppend(&t, items, nitems);
    } else {
        TarName *names = NULL;
        size_t nnames = 0;
        char *base = NULL;
        for (size_t i = 0; i < nitems; i++) {
            if (items[i].chdir) {
                char *nb = base && items[i].value[0] != '/' ? tarJoin(base, items[i].value) : strdup(items[i].value);
                free(base);
                base = nb;
                continue;
            }
            names = (TarName *)realloc(names, (nnames + 1) * sizeof(TarName));
            char *pat = strdup(items[i].value);
            size_t pl = strlen(pat);
            while (pl > 1 && pat[pl - 1] == '/') pat[--pl] = '\0';
            names[nnames].pat = pat;
            names[nnames].found = false;
            nnames++;
        }
        status = tarReadArchive(&t, names, nnames, base);
        for (size_t i = 0; i < nnames; i++) free(names[i].pat);
        free(names);
        free(base);
    }
    if (t.status == 2 && !t.fatal) {
        fflush(stdout);
        fputs("tar: Exiting with failure status due to previous errors\n", stderr);
    }
done:
    fflush(stdout);
    for (size_t i = 0; i < nitems; i++) free(items[i].value);
    free(items);
    for (size_t i = 0; i < t.nexcludes; i++) free(t.excludes[i]);
    free(t.excludes);
    for (size_t i = 0; i < t.nlinks; i++) free(t.links[i].name);
    free(t.links);
    free(t.delayed);
    gnuModeFree(&t.modeChange);
    gnuGetoptFree(&g);
    for (int i = 0; i < nallocated; i++) free(allocated[i]);
    free(allocated);
    free(built);
    return status;
}
