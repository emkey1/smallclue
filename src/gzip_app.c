/*
 * gzip, gunzip, zcat: GNU gzip 1.13 compatible, over zlib's raw deflate and
 * inflate with GNU's header (name and mtime unless -n, XFL by level, OS 3)
 * written here. In place by default with the input's mode, owner and times
 * kept and the input removed (unless -k/-c); -d -t -l (and -lv) -v -f -r
 * -q -N/-n -S -1..-9; GNU's suffixes (.gz -gz .z -z _z .Z .tgz .taz), its
 * refusals (a directory, a link, another hard link, an existing output, a
 * terminal) as warnings with exit status 2, concatenated members, trailing
 * garbage, -dcf passing other data through, and its messages.
 */

#include "gzip_app.h"

#include "app_hooks.h"
#include "gnu_getopt.h"
#include "gnu_util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

enum { GZ_COMPRESS, GZ_DECOMPRESS, GZ_TEST, GZ_LIST };

typedef struct {
    int mode, level;
    bool toStdout, force, keep, recursive, quiet, verbose, saveName, restoreName;
    const char *suffix;
    int status;          /* 0, 2 warning, 1 error */
    bool listed;
    uintmax_t totComp, totUncomp, lastOverhead;
    int nlisted;
} Gz;

typedef struct {
    int fd;
    unsigned char buf[65536];
    size_t len, pos;
    bool eof, err;
    uintmax_t consumed;
    int back[4], nback;   /* bytes pushed back, last first */
} GzIn;

static void gzWarn(Gz *g) {
    if (g->status == 0) g->status = 2;
}

static void gzUnget(GzIn *in, int c) {
    in->back[in->nback++] = c;
    in->consumed--;
}

static int gzByte(GzIn *in) {
    if (in->nback) {
        in->consumed++;
        return in->back[--in->nback];
    }
    if (in->pos == in->len) {
        if (in->eof) return -1;
        ssize_t n;
        do n = read(in->fd, in->buf, sizeof(in->buf));
        while (n < 0 && errno == EINTR);
        if (n <= 0) {
            in->eof = true;
            in->err = n < 0;
            return -1;
        }
        in->len = (size_t)n;
        in->pos = 0;
    }
    in->consumed++;
    return in->buf[in->pos++];
}

static bool gzWriteAll(int fd, const void *b, size_t n) {
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

static const char *gzBase(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Compress in -> out; false (after the message) on failure. */
static bool gzCompress(Gz *g, int in, int out, const char *inName, const char *storeName, uint32_t mtime,
                       uintmax_t *rawIn, uintmax_t *rawOut) {
    char q[4096];
    unsigned char hdr[10] = {0x1f, 0x8b, 8, (unsigned char)(storeName ? 8 : 0), 0, 0, 0, 0, 0, 3};
    hdr[4] = (unsigned char)mtime;
    hdr[5] = (unsigned char)(mtime >> 8);
    hdr[6] = (unsigned char)(mtime >> 16);
    hdr[7] = (unsigned char)(mtime >> 24);
    hdr[8] = g->level == 9 ? 2 : g->level == 1 ? 4 : 0;
    if (!gzWriteAll(out, hdr, 10)) goto werr;
    uintmax_t outBytes = 10;
    if (storeName) {
        size_t nl = strlen(storeName) + 1;
        if (!gzWriteAll(out, storeName, nl)) goto werr;
        outBytes += nl;
    }
    z_stream z;
    memset(&z, 0, sizeof(z));
    if (deflateInit2(&z, g->level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fputs("gzip: out of memory\n", stderr);
        return false;
    }
    unsigned char ibuf[65536], obuf[65536];
    uLong crc = crc32(0, NULL, 0);
    uintmax_t total = 0, deflated = 0;
    int flush = Z_NO_FLUSH;
    do {
        ssize_t n;
        do n = read(in, ibuf, sizeof(ibuf));
        while (n < 0 && errno == EINTR);
        if (n < 0) {
            fprintf(stderr, "gzip: %s: %s\n", inName, strerror(errno));
            deflateEnd(&z);
            return false;
        }
        if (n == 0) flush = Z_FINISH;
        crc = crc32(crc, ibuf, (uInt)n);
        total += (uintmax_t)n;
        z.next_in = ibuf;
        z.avail_in = (uInt)n;
        do {
            z.next_out = obuf;
            z.avail_out = sizeof(obuf);
            deflate(&z, flush);
            size_t have = sizeof(obuf) - z.avail_out;
            if (!gzWriteAll(out, obuf, have)) {
                deflateEnd(&z);
                goto werr;
            }
            deflated += have;
        } while (z.avail_out == 0);
    } while (flush != Z_FINISH);
    deflateEnd(&z);
    unsigned char tr[8] = {(unsigned char)crc, (unsigned char)(crc >> 8), (unsigned char)(crc >> 16),
                           (unsigned char)(crc >> 24), (unsigned char)total, (unsigned char)(total >> 8),
                           (unsigned char)(total >> 16), (unsigned char)(total >> 24)};
    if (!gzWriteAll(out, tr, 8)) goto werr;
    *rawIn = total;
    *rawOut = deflated;
    (void)outBytes;
    return true;
werr:
    fprintf(stderr, "gzip: %s: %s\n", g->toStdout ? "stdout" : gnuQuoteMaybe(inName, q, sizeof(q)), strerror(errno));
    return false;
}

typedef struct {
    uint32_t mtime, crc, isize;
    char name[1024];
    bool hasName;
    uintmax_t hdrLen;     /* header bytes, for the ratio */
    uintmax_t produced;   /* bytes inflated, all members */
    bool trailing;        /* data after the last member: GNU's ratio then counts it all */
} GzMember;

/* Reads a member header; 0 ok, 1 not gzip, 2 truncated, 3 bad flags. */
static int gzHeader(GzIn *in, GzMember *m) {
    int a = gzByte(in), b = gzByte(in);
    if (a < 0) return 2;
    if (a != 0x1f || b != 0x8b) return 1;
    int meth = gzByte(in), flags = gzByte(in);
    if (meth != 8) return 1;
    if (flags < 0) return 2;
    if (flags & 0xe0) return 3;
    uint32_t t = 0;
    for (int i = 0; i < 4; i++) {
        int c = gzByte(in);
        if (c < 0) return 2;
        t |= (uint32_t)c << (8 * i);
    }
    m->mtime = t;
    if (gzByte(in) < 0 || gzByte(in) < 0) return 2;
    if (flags & 4) {
        int lo = gzByte(in), hi = gzByte(in);
        if (hi < 0) return 2;
        for (int n = lo | hi << 8; n; n--)
            if (gzByte(in) < 0) return 2;
    }
    m->hasName = false;
    if (flags & 8) {
        size_t k = 0;
        int c;
        while ((c = gzByte(in)) > 0)
            if (k + 1 < sizeof(m->name)) m->name[k++] = (char)c;
        if (c < 0) return 2;
        m->name[k] = '\0';
        m->hasName = true;
    }
    if (flags & 16) {
        int c;
        while ((c = gzByte(in)) > 0) {}
        if (c < 0) return 2;
    }
    if (flags & 2) {
        if (gzByte(in) < 0 || gzByte(in) < 0) return 2;
    }
    return 0;
}

/* Decompress (or test, with out < 0); 0 ok, 1 error (message printed). */
static int gzDecompress(Gz *g, GzIn *in, int out, const char *inName, GzMember *firstMember, bool *passedThrough,
                        bool announce) {
    uintmax_t produced = 0;
    char q[4096];
    const char *nm = gnuQuoteMaybe(inName, q, sizeof(q));
    *passedThrough = false;
    int c0 = gzByte(in);
    if (c0 < 0) {
        if (g->force && g->toStdout && g->mode == GZ_DECOMPRESS) return 0;
        fprintf(stderr, "\ngzip: %s: unexpected end of file\n", nm);
        return 1;
    }
    gzUnget(in, c0);
    for (int member = 0;; member++) {
        GzMember m;
        memset(&m, 0, sizeof(m));
        int h = gzHeader(in, &m);
        if (h == 1 && member == 0 && g->force && g->toStdout && g->mode == GZ_DECOMPRESS) {
            /* -dcf: not ours, so copy it as it is */
            gzWriteAll(out, in->buf, in->len);
            ssize_t n;
            while ((n = read(in->fd, in->buf, sizeof(in->buf))) > 0) gzWriteAll(out, in->buf, (size_t)n);
            *passedThrough = true;
            return 0;
        }
        if (h == 1) {
            fprintf(stderr, "\ngzip: %s: not in gzip format\n", nm);
            return 1;
        }
        if (h == 3) {
            fprintf(stderr, "\ngzip: %s: has flags 0x%x -- not supported\n", nm, 0);
            return 1;
        }
        if (h == 2) {
            fprintf(stderr, "\ngzip: %s: unexpected end of file\n", nm);
            return 1;
        }
        if (member == 0) {
            m.hdrLen = in->consumed;
            if (firstMember) *firstMember = m;
            /* -v names the file once its header is good, as GNU does */
            if (announce) fprintf(stderr, "%s:\t", inName);
        }
        z_stream z;
        memset(&z, 0, sizeof(z));
        inflateInit2(&z, -15);
        unsigned char obuf[65536];
        uLong crc = crc32(0, NULL, 0);
        uint32_t size = 0;
        int rc = Z_OK;
        while (rc != Z_STREAM_END) {
            if (in->pos == in->len) {
                if (gzByte(in) < 0) {
                    inflateEnd(&z);
                    fprintf(stderr, "\ngzip: %s: unexpected end of file\n", nm);
                    return 1;
                }
                in->pos--;
                in->consumed--;
            }
            z.next_in = in->buf + in->pos;
            z.avail_in = (uInt)(in->len - in->pos);
            z.next_out = obuf;
            z.avail_out = sizeof(obuf);
            rc = inflate(&z, Z_NO_FLUSH);
            if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                inflateEnd(&z);
                fprintf(stderr, "\ngzip: %s: invalid compressed data--format violated\n", nm);
                return 1;
            }
            size_t used = (in->len - in->pos) - z.avail_in;
            in->pos += used;
            in->consumed += used;
            size_t have = sizeof(obuf) - z.avail_out;
            crc = crc32(crc, obuf, (uInt)have);
            size += (uint32_t)have;
            produced += have;
            if (firstMember) firstMember->produced = produced;
            if (out >= 0 && have && !gzWriteAll(out, obuf, have)) {
                inflateEnd(&z);
                fprintf(stderr, "gzip: %s: %s\n", g->toStdout ? "stdout" : nm, strerror(errno));
                return 1;
            }
        }
        inflateEnd(&z);
        uint32_t tcrc = 0, tsize = 0;
        for (int i = 0; i < 8; i++) {
            int c = gzByte(in);
            if (c < 0) {
                fprintf(stderr, "\ngzip: %s: unexpected end of file\n", nm);
                return 1;
            }
            if (i < 4) tcrc |= (uint32_t)c << (8 * i);
            else tsize |= (uint32_t)c << (8 * (i - 4));
        }
        if (tcrc != (uint32_t)crc) {
            fprintf(stderr, "\ngzip: %s: invalid compressed data--crc error\n", nm);
            return 1;
        }
        if (tsize != size) {
            fprintf(stderr, "\ngzip: %s: invalid compressed data--length error\n", nm);
            return 1;
        }
        /* another member, trailing zeros, garbage, or the end */
        int n0 = gzByte(in);
        if (n0 < 0) return 0;
        int n1 = gzByte(in);
        if (n0 == 0x1f && n1 == 0x8b) {
            gzUnget(in, n1);
            gzUnget(in, n0);
            continue;
        }
        if (firstMember) firstMember->trailing = true;
        bool zeros = n0 == 0 && n1 <= 0;
        if (n0 == 0 && n1 == 0) {
            int c;
            while ((c = gzByte(in)) == 0) {}
            zeros = c < 0;
        }
        if (zeros) {
            /* padding (tapes, block devices): GNU says so only with -v */
            if (g->verbose) {
                fprintf(stderr, "\ngzip: %s: decompression OK, trailing zero bytes ignored\n", nm);
                gzWarn(g);
            }
            return 0;
        }
        if (!g->quiet) fprintf(stderr, "\ngzip: %s: decompression OK, trailing garbage ignored\n", nm);
        gzWarn(g);
        return 0;
    }
    return 0;
}

static const char *const gzKnownSuffixes[] = {".gz", "-gz", ".z", "-z", "_z", ".Z", NULL};

/* The name after decompression, or NULL when the suffix is unknown. */
static char *gzStrip(const Gz *g, const char *name) {
    size_t n = strlen(name);
    const char *base = gzBase(name);
    size_t bl = strlen(base);
    if (g->suffix && strcmp(g->suffix, ".gz")) {
        size_t sl = strlen(g->suffix);
        if (bl > sl && !strcmp(name + n - sl, g->suffix)) return strndup(name, n - sl);
    }
    for (int i = 0; gzKnownSuffixes[i]; i++) {
        size_t sl = strlen(gzKnownSuffixes[i]);
        if (bl > sl && !strcmp(name + n - sl, gzKnownSuffixes[i])) return strndup(name, n - sl);
    }
    if (bl > 4 && (!strcmp(name + n - 4, ".tgz") || !strcmp(name + n - 4, ".taz"))) {
        char *r = strndup(name, n - 3);
        r = (char *)realloc(r, n + 2);
        strcpy(r + n - 3, "tar");
        return r;
    }
    return NULL;
}

static bool gzHasSuffix(const Gz *g, const char *name) {
    size_t n = strlen(name), sl = strlen(g->suffix);
    if (n > sl && !strcmp(name + n - sl, g->suffix)) return true;
    for (int i = 0; gzKnownSuffixes[i]; i++) {
        size_t kl = strlen(gzKnownSuffixes[i]);
        if (n > kl && !strcmp(name + n - kl, gzKnownSuffixes[i])) return true;
    }
    return n > 4 && (!strcmp(name + n - 4, ".tgz") || !strcmp(name + n - 4, ".taz"));
}

static void gzRatio(FILE *f, uintmax_t num, uintmax_t den) {
    fprintf(f, "%5.1f%%", den == 0 ? 0.0 : 100.0 * ((double)den - (double)num) / (double)den);
}

static void gzListHeader(Gz *g) {
    if (g->listed) return;
    g->listed = true;
    if (g->verbose) fputs("method  crc     date  time  ", stdout);
    puts("         compressed        uncompressed  ratio uncompressed_name");
}

static void gzOne(Gz *g, const char *name);

static void gzDir(Gz *g, const char *dir) {
    char q[4096];
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "gzip: %s: %s\n", gnuQuoteMaybe(dir, q, sizeof(q)), strerror(errno));
        g->status = 1;
        return;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        size_t n = strlen(dir) + strlen(e->d_name) + 2;
        char *p = (char *)malloc(n);
        snprintf(p, n, "%s/%s", dir, e->d_name);
        gzOne(g, p);
        free(p);
    }
    closedir(d);
}

/* Copy mode, owner and times from st to the open output. */
static void gzKeepAttrs(int fd, const struct stat *st, bool fromHeader, uint32_t mtime) {
    struct timespec ts[2];
#if defined(__APPLE__) && !defined(st_mtim)
    ts[0] = st->st_atimespec;
    ts[1] = st->st_mtimespec;
#else
    ts[0] = st->st_atim;
    ts[1] = st->st_mtim;
#endif
    if (fromHeader && mtime) {
        ts[1].tv_sec = (time_t)mtime;
        ts[1].tv_nsec = 0;
    }
    if (fchown(fd, st->st_uid, st->st_gid) != 0) {
        if (fchown(fd, (uid_t)-1, st->st_gid) != 0) {}
    }
    fchmod(fd, st->st_mode & 07777);
    futimens(fd, ts);
}

static void gzStdin(Gz *g) {
    if (g->mode == GZ_COMPRESS && isatty(STDOUT_FILENO) && !g->force) {
        fputs("gzip: compressed data not written to a terminal. Use -f to force compression.\n"
              "For help, type: gzip -h\n",
              stderr);
        g->status = 1;
        return;
    }
    if (g->mode == GZ_DECOMPRESS && isatty(STDIN_FILENO) && !g->force) {
        fputs("gzip: compressed data not read from a terminal. Use -f to force decompression.\n"
              "For help, type: gzip -h\n",
              stderr);
        g->status = 1;
        return;
    }
    struct stat st;
    uint32_t mtime = 0;
    if (g->saveName && fstat(STDIN_FILENO, &st) == 0 && S_ISREG(st.st_mode)) mtime = (uint32_t)st.st_mtime;
    uintmax_t in = 0, out = 0;
    if (g->mode == GZ_COMPRESS) {
        if (!gzCompress(g, STDIN_FILENO, STDOUT_FILENO, "stdin", NULL, mtime, &in, &out)) g->status = 1;
        else if (g->verbose) {
            gzRatio(stderr, out, in);
            fputc('\n', stderr);
        }
        return;
    }
    GzIn gi;
    memset(&gi, 0, sizeof(gi));
    gi.fd = STDIN_FILENO;
    bool pass;
    if (gzDecompress(g, &gi, g->mode == GZ_TEST ? -1 : STDOUT_FILENO, "stdin", NULL, &pass, false)) g->status = 1;
    else if (g->mode == GZ_TEST && g->verbose) fputs(" OK\n", stderr);
}

static void gzOne(Gz *g, const char *name) {
    char q[4096], q2[4096];
    if (!strcmp(name, "-")) {
        gzStdin(g);
        return;
    }
    const char *nm = gnuQuoteMaybe(name, q, sizeof(q));
    struct stat st;
    if (lstat(name, &st) != 0) {
        /* gunzip foo means foo.gz */
        if (errno == ENOENT && g->mode != GZ_COMPRESS) {
            char *alt = (char *)malloc(strlen(name) + strlen(g->suffix) + 1);
            sprintf(alt, "%s%s", name, g->suffix);
            if (lstat(alt, &st) == 0) {
                gzOne(g, alt);
                free(alt);
                return;
            }
            fprintf(stderr, "gzip: %s: %s\n", gnuQuoteMaybe(alt, q2, sizeof(q2)), strerror(ENOENT));
            free(alt);
            g->status = 1;
            return;
        }
        fprintf(stderr, "gzip: %s: %s\n", nm, strerror(errno));
        g->status = 1;
        return;
    }
    if (S_ISLNK(st.st_mode) && !g->force && !g->toStdout) {
        fprintf(stderr, "gzip: %s: Too many levels of symbolic links\n", nm);
        g->status = 1;
        return;
    }
    if (stat(name, &st) != 0) {
        fprintf(stderr, "gzip: %s: %s\n", nm, strerror(errno));
        g->status = 1;
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        if (g->recursive) {
            gzDir(g, name);
            return;
        }
        if (!g->quiet) fprintf(stderr, "gzip: %s is a directory -- ignored\n", nm);
        gzWarn(g);
        return;
    }
    if (!S_ISREG(st.st_mode) && !g->toStdout) {
        if (!g->quiet) fprintf(stderr, "gzip: %s is not a directory or a regular file - ignored\n", nm);
        gzWarn(g);
        return;
    }
    if (g->mode == GZ_COMPRESS && !g->toStdout && gzHasSuffix(g, name)) {
        if (g->recursive) return;
        if (!g->quiet) fprintf(stderr, "gzip: %s already has %s suffix -- unchanged\n", nm, g->suffix);
        return;
    }
    if (!g->toStdout && g->mode != GZ_TEST && g->mode != GZ_LIST && st.st_nlink > 1 && !g->force) {
        if (!g->quiet)
            fprintf(stderr, "gzip: %s has %ju other link%s -- file ignored\n", nm, (uintmax_t)st.st_nlink - 1,
                    st.st_nlink > 2 ? "s" : "");
        gzWarn(g);
        return;
    }
    char *outName = NULL;
    if (g->mode == GZ_COMPRESS) {
        outName = (char *)malloc(strlen(name) + strlen(g->suffix) + 1);
        sprintf(outName, "%s%s", name, g->suffix);
    } else if (g->mode == GZ_DECOMPRESS && !g->toStdout) {
        outName = gzStrip(g, name);
        if (!outName) {
            if (!g->quiet) fprintf(stderr, "gzip: %s: unknown suffix -- ignored\n", nm);
            gzWarn(g);
            return;
        }
        if (g->restoreName) {
            /* -N: the stored name, beside the input -- known before the output exists */
            GzIn hi;
            memset(&hi, 0, sizeof(hi));
            hi.fd = open(name, O_RDONLY);
            GzMember hm;
            memset(&hm, 0, sizeof(hm));
            if (hi.fd >= 0 && gzHeader(&hi, &hm) == 0 && hm.hasName && hm.name[0] && !strchr(hm.name, '/')) {
                size_t dl = (size_t)(gzBase(name) - name);
                char *want = (char *)malloc(dl + strlen(hm.name) + 1);
                memcpy(want, name, dl);
                strcpy(want + dl, hm.name);
                free(outName);
                outName = want;
            }
            if (hi.fd >= 0) close(hi.fd);
        }
    }
    int in = open(name, O_RDONLY | (g->force ? 0 : O_NOFOLLOW));
    if (in < 0) {
        fprintf(stderr, "gzip: %s: %s\n", nm, strerror(errno));
        g->status = 1;
        free(outName);
        return;
    }
    if (g->mode == GZ_LIST) {
        GzIn gi;
        memset(&gi, 0, sizeof(gi));
        gi.fd = in;
        GzMember m;
        memset(&m, 0, sizeof(m));
        int h = gzHeader(&gi, &m);
        if (h) {
            fprintf(stderr, "gzip: %s: not in gzip format\n", nm);
            g->status = 1;
            close(in);
            return;
        }
        unsigned char tr[8];
        uint32_t crc = 0, isize = 0;
        if (lseek(in, -8, SEEK_END) >= 0 && read(in, tr, 8) == 8) {
            crc = (uint32_t)tr[0] | (uint32_t)tr[1] << 8 | (uint32_t)tr[2] << 16 | (uint32_t)tr[3] << 24;
            isize = (uint32_t)tr[4] | (uint32_t)tr[5] << 8 | (uint32_t)tr[6] << 16 | (uint32_t)tr[7] << 24;
        }
        close(in);
        uintmax_t comp = (uintmax_t)st.st_size;
        uintmax_t headerLen = gi.consumed;
        gzListHeader(g);
        char *un = gzStrip(g, name);
        if (g->verbose) {
            char date[32];
            time_t t = (time_t)m.mtime;
            struct tm tm;
            localtime_r(&t, &tm);
            strftime(date, sizeof(date), "%b %e %H:%M", &tm);
            printf("defla %08x %s ", crc, date);
        }
        printf("%19ju %19ju ", comp, (uintmax_t)isize);
        gzRatio(stdout, comp > headerLen + 8 ? comp - headerLen - 8 : 0, isize);
        printf(" %s\n", un ? un : name);
        free(un);
        g->totComp += comp;
        g->lastOverhead = headerLen + 8;
        g->totUncomp += isize;
        g->nlisted++;
        return;
    }
    int out = -1;
    if (g->toStdout) {
        out = STDOUT_FILENO;
    } else if (outName) {
        struct stat ost;
        if (lstat(outName, &ost) == 0) {
            bool overwrite = g->force;
            if (!overwrite && isatty(STDIN_FILENO) && !g->quiet) {
                fprintf(stderr, "gzip: %s already exists; do you wish to overwrite (y or n)? ", gnuQuoteMaybe(outName, q2, sizeof(q2)));
                overwrite = gnuYes();
            } else if (!overwrite) {
                fprintf(stderr, "gzip: %s already exists;\tnot overwritten\n", gnuQuoteMaybe(outName, q2, sizeof(q2)));
            }
            if (!overwrite) {
                gzWarn(g);
                close(in);
                free(outName);
                return;
            }
            unlink(outName);
        }
        out = open(outName, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (out < 0) {
            fprintf(stderr, "gzip: %s: %s\n", gnuQuoteMaybe(outName, q2, sizeof(q2)), strerror(errno));
            g->status = 1;
            close(in);
            free(outName);
            return;
        }
    }
    bool ok;
    uintmax_t rawIn = 0, rawOut = 0;
    GzMember m;
    memset(&m, 0, sizeof(m));
    if (g->mode == GZ_COMPRESS) {
        const char *store = g->saveName ? gzBase(name) : NULL;
        ok = gzCompress(g, in, out, name, store, g->saveName ? (uint32_t)st.st_mtime : 0, &rawIn, &rawOut);
    } else {
        GzIn gi;
        memset(&gi, 0, sizeof(gi));
        gi.fd = in;
        bool pass;
        ok = gzDecompress(g, &gi, g->mode == GZ_TEST ? -1 : out, name, &m, &pass, g->verbose) == 0;
        rawIn = (uintmax_t)st.st_size;
    }
    close(in);
    if (!ok) {
        g->status = 1;
        if (out >= 0 && out != STDOUT_FILENO) {
            close(out);
            unlink(outName);
        }
        free(outName);
        return;
    }
    if (out >= 0 && out != STDOUT_FILENO) {
        gzKeepAttrs(out, &st, g->mode == GZ_DECOMPRESS && g->restoreName, m.mtime);
        if (close(out) != 0) {
            fprintf(stderr, "gzip: %s: %s\n", gnuQuoteMaybe(outName, q2, sizeof(q2)), strerror(errno));
            g->status = 1;
            free(outName);
            return;
        }
    }
    if (g->verbose) {
        if (g->mode == GZ_TEST) {
            fputs(" OK\n", stderr);
        } else {
            if (g->mode == GZ_COMPRESS) {
                fprintf(stderr, "%s:\t", name);
                gzRatio(stderr, rawOut, rawIn);
            } else {
                uintmax_t over = m.trailing ? 0 : m.hdrLen + 8;
                gzRatio(stderr, rawIn > over ? rawIn - over : 0, m.produced);
            }
            fprintf(stderr, " -- replaced with %s\n", g->toStdout ? "stdout" : outName);
        }
    }
    if (!g->toStdout && !g->keep && g->mode != GZ_TEST && unlink(name) != 0) {
        fprintf(stderr, "gzip: %s: %s\n", nm, strerror(errno));
        g->status = 1;
    }
    free(outName);
}

static const GnuLongOpt gzLongs[] = {
    {"stdout", GNU_NO_ARG, 'c'},   {"to-stdout", GNU_NO_ARG, 'c'}, {"decompress", GNU_NO_ARG, 'd'},
    {"uncompress", GNU_NO_ARG, 'd'}, {"force", GNU_NO_ARG, 'f'},   {"help", GNU_NO_ARG, 'h'},
    {"keep", GNU_NO_ARG, 'k'},     {"list", GNU_NO_ARG, 'l'},      {"license", GNU_NO_ARG, 'L'},
    {"no-name", GNU_NO_ARG, 'n'},  {"name", GNU_NO_ARG, 'N'},      {"quiet", GNU_NO_ARG, 'q'},
    {"silent", GNU_NO_ARG, 'q'},   {"recursive", GNU_NO_ARG, 'r'}, {"suffix", GNU_REQ_ARG, 'S'},
    {"test", GNU_NO_ARG, 't'},     {"verbose", GNU_NO_ARG, 'v'},   {"version", GNU_NO_ARG, 'V'},
    {"fast", GNU_NO_ARG, '1'},     {"best", GNU_NO_ARG, '9'},      {"rsyncable", GNU_NO_ARG, 1},
    {"synchronous", GNU_NO_ARG, 2},
};

static int gzMain(int argc, char **argv, int mode, bool toStdout) {
    Gz g;
    memset(&g, 0, sizeof(g));
    g.mode = mode;
    g.level = 6;
    g.toStdout = toStdout;
    g.saveName = true;
    g.suffix = ".gz";
    GnuGetopt o;
    gnuGetoptInit(&o, argc, argv, "gzip", "123456789cdfhklLnNqrS:tvV", gzLongs, sizeof(gzLongs) / sizeof(gzLongs[0]));
    int c;
    bool nameSet = false;
    while ((c = gnuGetopt(&o)) != -1) {
        switch (c) {
        case 'c': g.toStdout = true; break;
        case 'd': if (g.mode == GZ_COMPRESS) g.mode = GZ_DECOMPRESS; break;
        case 'f': g.force = true; break;
        case 'k': g.keep = true; break;
        case 'l': g.mode = GZ_LIST; break;
        case 'n': g.saveName = false; g.restoreName = false; nameSet = true; break;
        case 'N': g.saveName = true; g.restoreName = true; nameSet = true; break;
        case 'q': g.quiet = true; g.verbose = false; break;
        case 'r': g.recursive = true; break;
        case 'S':
            if (!*o.arg || strchr(o.arg, '/')) {
                fprintf(stderr, "gzip: invalid suffix '%s'\n", o.arg);
                gnuGetoptFree(&o);
                return 1;
            }
            g.suffix = o.arg;
            break;
        case 't': g.mode = GZ_TEST; break;
        case 'v': g.verbose = true; g.quiet = false; break;
        case 1: case 2: break;
        case 'h':
            puts("Usage: gzip [OPTION]... [FILE]...\n"
                 "Compress or uncompress FILEs (by default, compress FILES in-place).\n\n"
                 "  -c, --stdout      write on standard output, keep original files unchanged\n"
                 "  -d, --decompress  decompress\n"
                 "  -f, --force       force overwrite of output file and compress links\n"
                 "  -k, --keep        keep (don't delete) input files\n"
                 "  -l, --list        list compressed file contents\n"
                 "  -n, --no-name     do not save or restore the original name and timestamp\n"
                 "  -N, --name        save or restore the original name and timestamp\n"
                 "  -q, --quiet       suppress all warnings\n"
                 "  -r, --recursive   operate recursively on directories\n"
                 "  -S, --suffix=SUF  use suffix SUF on compressed files\n"
                 "  -t, --test        test compressed file integrity\n"
                 "  -v, --verbose     verbose mode\n"
                 "  -1, --fast        compress faster\n"
                 "  -9, --best        compress better\n\n"
                 "With no FILE, or when FILE is -, read standard input.");
            gnuGetoptFree(&o);
            return 0;
        case 'V': case 'L': puts("gzip 1.13 (SmallCLUE)"); gnuGetoptFree(&o); return 0;
        default:
            if (c >= '1' && c <= '9') {
                g.level = c - '0';
                break;
            }
            fputs("Try `gzip --help' for more information.\n", stderr);
            gnuGetoptFree(&o);
            return 1;
        }
    }
    (void)nameSet;
    if (g.mode == GZ_TEST) g.toStdout = false;
    if (o.nops == 0) {
        if (g.mode == GZ_LIST) {
            fputs("gzip: stdin: not in gzip format\n", stderr);
            g.status = 1;
        } else {
            gzStdin(&g);
        }
    } else {
        for (int i = 0; i < o.nops; i++) gzOne(&g, o.ops[i]);
    }
    if (g.mode == GZ_LIST && g.nlisted > 1) {
        printf("%19ju %19ju ", g.totComp, g.totUncomp);
        gzRatio(stdout, g.totComp > g.lastOverhead ? g.totComp - g.lastOverhead : 0, g.totUncomp);   /* GNU subtracts one header */
        puts(" (totals)");
    }
    gnuGetoptFree(&o);
    fflush(stdout);
    return g.status;
}

int smallclueGzipCommand(int argc, char **argv) {
    return gzMain(argc, argv, GZ_COMPRESS, false);
}

int smallclueGunzipCommand(int argc, char **argv) {
    return gzMain(argc, argv, GZ_DECOMPRESS, false);
}

int smallclueZcatCommand(int argc, char **argv) {
    return gzMain(argc, argv, GZ_DECOMPRESS, true);
}
