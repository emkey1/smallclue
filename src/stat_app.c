/*
 * stat: GNU coreutils 9 compatible. Every file and file-system directive
 * with printf flags, width and precision (%.9Y style sub-second times),
 * %Hd/%Ld/%Hr/%Lr, -c and --printf (with its escapes), -L, -f, -t, the
 * default and terse layouts, "-" for standard input, and GNU's messages.
 * Birth times are unknown ("-", 0), as GNU reports them on AOK's
 * filesystems.
 */

#include "stat_app.h"

#include "gnu_getopt.h"
#include "gnu_mode.h"
#include "gnu_util.h"

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#else
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#endif

#if defined(__APPLE__) && !defined(st_atim)
#define STAT_ATIM(st) ((st)->st_atimespec)
#define STAT_MTIM(st) ((st)->st_mtimespec)
#define STAT_CTIM(st) ((st)->st_ctimespec)
#define STAT_FSID(fs, i) ((uint32_t)(fs)->f_fsid.val[i])
#else
#define STAT_ATIM(st) ((st)->st_atim)
#define STAT_MTIM(st) ((st)->st_mtim)
#define STAT_CTIM(st) ((st)->st_ctim)
#define STAT_FSID(fs, i) ((uint32_t)(fs)->f_fsid.__val[i])
#endif

enum { STAT_Q_LITERAL, STAT_Q_SHELL, STAT_Q_ALWAYS, STAT_Q_C };

typedef struct {
    const char *name;
    int quoting;     /* %N: literal for the default layout, QUOTING_STYLE else */
    bool fs;
    struct stat st;
    struct statfs sfs;
    struct statvfs svfs;
    bool deref;
} StatTarget;

/* Writes `pre` (a "%flags width .prec" prefix of plen bytes) with `conv`
 * appended, applied to the value -- keeping only the flags GNU's make_format
 * allows that conversion ("'-+ 0" signed, "'-0" unsigned, "'-#0" octal and
 * hex, "-" strings). */
static void statOut(const char *pre, size_t plen, const char *conv, ...) {
    const char *allowed = conv[1] == 'd' ? "'-+ 0" : conv[1] == 'u' ? "'-0" : conv[0] == 's' ? "-" : "'-#0";
    char fmt[64];
    size_t n = 0, i = 0;
    if (plen && pre[0] == '%') fmt[n++] = pre[i++];
    for (; i < plen && strchr("'-+ #0", pre[i]); i++)
        if (strchr(allowed, pre[i]) && n < sizeof(fmt) - 8) fmt[n++] = pre[i];
    for (; i < plen && n < sizeof(fmt) - 8; i++) fmt[n++] = pre[i];
    strcpy(fmt + n, conv);
    va_list ap;
    va_start(ap, conv);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

#define STAT_INT(v) statOut(pre, plen, "jd", (intmax_t)(v))
#define STAT_UINT(v) statOut(pre, plen, "ju", (uintmax_t)(v))
#define STAT_OCT(v) statOut(pre, plen, "jo", (uintmax_t)(v))
#define STAT_HEX(v) statOut(pre, plen, "jx", (uintmax_t)(v))
#define STAT_STR(v) statOut(pre, plen, "s", (const char *)(v))

static const char *statFileType(const struct stat *st) {
    mode_t m = st->st_mode;
    if (S_ISREG(m)) return st->st_size == 0 ? "regular empty file" : "regular file";
    if (S_ISDIR(m)) return "directory";
    if (S_ISLNK(m)) return "symbolic link";
    if (S_ISBLK(m)) return "block special file";
    if (S_ISCHR(m)) return "character special file";
    if (S_ISFIFO(m)) return "fifo";
    if (S_ISSOCK(m)) return "socket";
    return "weird file";
}

static void statModeString(mode_t m, char out[11]) {
    out[0] = S_ISREG(m) ? '-' : S_ISDIR(m) ? 'd' : S_ISLNK(m) ? 'l' : S_ISBLK(m) ? 'b' : S_ISCHR(m) ? 'c'
           : S_ISFIFO(m) ? 'p' : S_ISSOCK(m) ? 's' : '?';
    gnuModeString(m, out + 1);
}

/* "2001-02-03 04:05:06.500000000 +0000", in local time. */
static void statHuman(struct timespec ts, char *out, size_t n) {
    struct tm tm;
    time_t t = ts.tv_sec;
    if (!localtime_r(&t, &tm)) {
        snprintf(out, n, "%jd.%09ld", (intmax_t)t, (long)ts.tv_nsec);
        return;
    }
    char a[64], z[16];
    strftime(a, sizeof(a), "%Y-%m-%d %H:%M:%S", &tm);
    strftime(z, sizeof(z), "%z", &tm);
    snprintf(out, n, "%s.%09ld %s", a, (long)ts.tv_nsec, z);
}

/* GNU's out_epoch_sec: %Y-style seconds, with .PREC truncated digits. */
static void statEpoch(const char *pre, size_t plen, struct timespec ts) {
    char p[64];
    size_t n = plen < sizeof(p) - 1 ? plen : sizeof(p) - 1;
    memcpy(p, pre, n);
    p[n] = '\0';
    char *dot = strchr(p, '.');
    int precision = 0, width = 0;
    bool fracLeft = false;
    size_t secLen = n;
    if (dot) {
        secLen = (size_t)(dot - p);
        precision = isdigit((unsigned char)dot[1]) ? atoi(dot + 1) : 9;
        if (precision && dot > p && isdigit((unsigned char)dot[-1])) {
            char *q = dot;
            *dot = '\0';
            do --q; while (q > p && isdigit((unsigned char)q[-1]));
            width = atoi(q);
            if (width > 1) {
                q += *q == '0';
                secLen = (size_t)(q - p);
                int wd = width > 1 ? width - 1 : 0;
                if (wd > 1) {
                    int w = wd - precision;
                    if (w > 1) {
                        char *dst = p;
                        for (const char *src = p; src < q; src++) {
                            if (*src == '-') fracLeft = true;
                            else *dst++ = *src;
                        }
                        secLen = (size_t)(dst - p) + (fracLeft ? 0 : (size_t)sprintf(dst, "%d", w));
                    }
                }
            }
        }
    }
    int divisor = 1;
    for (int i = precision; i < 9; i++) divisor *= 10;
    long frac = ts.tv_nsec / divisor;
    intmax_t sec = ts.tv_sec;
    bool minusZero = false;
    if (sec < 0 && ts.tv_nsec != 0) {
        long modulus = 1000000000L / divisor;
        frac = modulus - frac - (ts.tv_nsec % divisor != 0);
        sec += frac != 0;
        minusZero = sec == 0;
    }
    if (minusZero) statOut(p, secLen, "s", "-0");
    else statOut(p, secLen, "jd", sec);
    if (precision) {
        int prec = precision < 9 ? precision : 9;
        printf(".%0*ld", prec, frac);
        for (int k = prec; k < precision; k++) putchar('0');
    }
}

/* The mount point: walk up while the device stays the same. */
static void statMountPoint(const char *name, char *out, size_t n) {
    char path[PATH_MAX];
    if (!realpath(name, path)) {
        snprintf(out, n, "?");
        return;
    }
    struct stat st, up;
    if (stat(path, &st) != 0) {
        snprintf(out, n, "?");
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        char *slash = strrchr(path, '/');
        if (slash == path) path[1] = '\0';
        else if (slash) *slash = '\0';
        if (stat(path, &st) != 0) {
            snprintf(out, n, "?");
            return;
        }
    }
    for (;;) {
        if (!strcmp(path, "/")) break;
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s", path);
        char *slash = strrchr(parent, '/');
        if (slash == parent) parent[1] = '\0';
        else if (slash) *slash = '\0';
        if (stat(parent, &up) != 0 || up.st_dev != st.st_dev) break;
        snprintf(path, sizeof(path), "%s", parent);
    }
    snprintf(out, n, "%s", path);
}

static const char *statFsName(uint32_t type, char *buf, size_t n) {
    static const struct { uint32_t magic; const char *name; } names[] = {
        {0xEF53, "ext2/ext3"}, {0x01021994, "tmpfs"}, {0x9FA0, "proc"}, {0x62656572, "sysfs"},
        {0x1CD1, "devpts"}, {0x858458F6, "ramfs"}, {0x6969, "nfs"}, {0x9123683E, "btrfs"},
        {0x58465342, "xfs"}, {0x4D44, "msdos"}, {0x65735546, "fuseblk"}, {0x65735543, "fusectl"},
        {0x794C7630, "overlayfs"}, {0x73717368, "squashfs"}, {0x63677270, "cgroup2fs"},
        {0x27E0EB, "cgroupfs"}, {0x9660, "isofs"}, {0x64626720, "debugfs"}, {0x73636673, "securityfs"},
        {0x19800202, "mqueue"}, {0x42494E4D, "binfmt_misc"}, {0x958458F6, "hugetlbfs"},
        {0x50495045, "pipefs"}, {0x534F434B, "sockfs"}, {0x74726163, "tracefs"}, {0x6E736673, "nsfs"},
        {0xCAFE4A11, "bpf_fs"}, {0x2011BAB0, "exfat"}, {0x5346544E, "ntfs"}, {0x137D, "ext"},
        {0x3153464A, "jfs"}, {0x52654973, "reiserfs"}, {0xF2F52010, "f2fs"}, {0x24051905, "ubifs"},
        {0x28CD3D45, "cramfs"}, {0x01161970, "gfs/gfs2"}, {0x47504653, "gpfs"}, {0x5A3C69F0, "aafs"},
        {0x13661366, "balloon-kvm-fs"}, {0x00C36400, "ceph"}, {0xFF534D42, "cifs"}, {0x73757245, "coda"},
        {0x453DCD28, "cramfs-wend"}, {0x1373, "devfs"}, {0xF15F, "ecryptfs"}, {0x414A53, "efs"},
        {0xDE5E81E4, "efivarfs"}, {0x2BAD1DEA, "inotifyfs"}, {0x5346414F, "afs"}, {0x9FA2, "usbdevfs"},
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (names[i].magic == type) return names[i].name;
    snprintf(buf, n, "UNKNOWN (0x%" PRIx32 ")", type);
    return buf;
}

static const char *statLiteral(const char *s, char *buf, size_t n) {
    snprintf(buf, n, "%s", s);
    return buf;
}

/* QUOTING_STYLE=c/escape: "name" with C escapes. */
static const char *statCQuote(const char *s, char *buf, size_t n) {
    size_t o = 0;
    if (n < 3) return "";
    buf[o++] = '"';
    for (; *s && o + 6 < n; s++) {
        unsigned char c = (unsigned char)*s;
        const char *hit = c ? strchr("\a\b\f\n\r\t\v\"\\", c) : NULL;
        if (hit) {
            buf[o++] = '\\';
            buf[o++] = "abfnrtv\"\\"[hit - "\a\b\f\n\r\t\v\"\\"];
        } else if (c < 0x20 || c == 0x7f) {
            o += (size_t)snprintf(buf + o, n - o, "\\%03o", c);
        } else {
            buf[o++] = (char)c;
        }
    }
    buf[o++] = '"';
    buf[o] = '\0';
    return buf;
}

/* One directive; false when it failed (%C). */
static bool statDirective(const StatTarget *t, const char *pre, size_t plen, char mod, char c) {
    const struct stat *st = &t->st;
    char buf[PATH_MAX * 2 + 64], q[PATH_MAX + 64], q2[PATH_MAX + 64];
    if (t->fs) {
        switch (c) {
        case 'a': STAT_INT(t->svfs.f_bavail); break;
        case 'b': STAT_INT(t->svfs.f_blocks); break;
        case 'c': STAT_INT(t->svfs.f_files); break;
        case 'd': STAT_INT(t->svfs.f_ffree); break;
        case 'f': STAT_INT(t->svfs.f_bfree); break;
        case 'i': STAT_HEX(((uintmax_t)STAT_FSID(&t->sfs, 0) << 32) | STAT_FSID(&t->sfs, 1)); break;
        case 'l': STAT_INT(t->svfs.f_namemax); break;
        case 'n': STAT_STR(t->name); break;
        case 's': STAT_INT(t->sfs.f_bsize); break;
        case 'S': STAT_INT(t->svfs.f_frsize); break;
        case 't': STAT_HEX((uint32_t)t->sfs.f_type); break;
        case 'T': STAT_STR(statFsName((uint32_t)t->sfs.f_type, buf, sizeof(buf))); break;
        default: putchar('?'); break;
        }
        return true;
    }
    switch (c) {
    case 'a': STAT_OCT(st->st_mode & 07777); break;
    case 'A': statModeString(st->st_mode, buf); STAT_STR(buf); break;
    case 'b': STAT_UINT(st->st_blocks); break;
    case 'B': STAT_UINT(512); break;
    case 'C': {
        fflush(stdout);
        fprintf(stderr, "stat: failed to get security context of %s: No data available\n",
                gnuQuote(t->name, q, sizeof(q)));
        STAT_STR("?");
        return false;
    }
    case 'd':
        if (mod == 'H') STAT_UINT(major(st->st_dev));
        else if (mod == 'L') STAT_UINT(minor(st->st_dev));
        else STAT_UINT(st->st_dev);
        break;
    case 'D': STAT_HEX(st->st_dev); break;
    case 'f': STAT_HEX(st->st_mode); break;
    case 'F': STAT_STR(statFileType(st)); break;
    case 'g': STAT_UINT(st->st_gid); break;
    case 'G': {
        struct group *gr = getgrgid(st->st_gid);
        STAT_STR(gr ? gr->gr_name : "UNKNOWN");
        break;
    }
    case 'h': STAT_UINT(st->st_nlink); break;
    case 'i': STAT_UINT(st->st_ino); break;
    case 'm': statMountPoint(t->name, buf, sizeof(buf)); STAT_STR(buf); break;
    case 'n': STAT_STR(t->name); break;
    case 'N': {
        const char *(*quote)(const char *, char *, size_t) =
            t->quoting == STAT_Q_SHELL ? gnuQuoteMaybe : t->quoting == STAT_Q_ALWAYS ? gnuQuote : statLiteral;
        if (t->quoting == STAT_Q_C) quote = statCQuote;
        if (S_ISLNK(st->st_mode)) {
            char target[PATH_MAX];
            ssize_t len = readlink(t->name, target, sizeof(target) - 1);
            if (len < 0) {
                fflush(stdout);
                fprintf(stderr, "stat: cannot read symbolic link %s: %s\n", gnuQuote(t->name, q, sizeof(q)),
                        strerror(errno));
                return false;
            }
            target[len] = '\0';
            snprintf(buf, sizeof(buf), "%s -> %s", quote(t->name, q, sizeof(q)), quote(target, q2, sizeof(q2)));
        } else {
            quote(t->name, buf, sizeof(buf));
        }
        STAT_STR(buf);
        break;
    }
    case 'o': STAT_UINT(st->st_blksize); break;
    case 'r':
        if (mod == 'H') STAT_UINT(major(st->st_rdev));
        else if (mod == 'L') STAT_UINT(minor(st->st_rdev));
        else STAT_UINT(st->st_rdev);
        break;
    case 'R': STAT_HEX(st->st_rdev); break;
    case 's': STAT_UINT(st->st_size); break;
    case 't': STAT_HEX(major(st->st_rdev)); break;
    case 'T': STAT_HEX(minor(st->st_rdev)); break;
    case 'u': STAT_UINT(st->st_uid); break;
    case 'U': {
        struct passwd *pw = getpwuid(st->st_uid);
        STAT_STR(pw ? pw->pw_name : "UNKNOWN");
        break;
    }
    case 'w': STAT_STR("-"); break;
    case 'W': STAT_INT(0); break;
    case 'x': statHuman(STAT_ATIM(st), buf, sizeof(buf)); STAT_STR(buf); break;
    case 'X': statEpoch(pre, plen, STAT_ATIM(st)); break;
    case 'y': statHuman(STAT_MTIM(st), buf, sizeof(buf)); STAT_STR(buf); break;
    case 'Y': statEpoch(pre, plen, STAT_MTIM(st)); break;
    case 'z': statHuman(STAT_CTIM(st), buf, sizeof(buf)); STAT_STR(buf); break;
    case 'Z': statEpoch(pre, plen, STAT_CTIM(st)); break;
    default: putchar('?'); break;
    }
    return true;
}

/* GNU's print_it; false when a directive failed. Exits (status 1) on an
 * invalid directive, as GNU does. */
static bool statPrint(const StatTarget *t, const char *format, bool escapes, int *fatal) {
    bool ok = true;
    char q[512];
    for (const char *b = format; *b; b++) {
        if (*b == '%') {
            const char *start = b;
            const char *p = b + 1;
            p += strspn(p, "'-+ #0I");
            p += strspn(p, "0123456789");
            if (*p == '.') {
                p++;
                p += strspn(p, "0123456789");
            }
            size_t plen = (size_t)(p - start);
            char fc = *p, mod = 0;
            if ((fc == 'H' || fc == 'L') && !t->fs && (p[1] == 'd' || p[1] == 'r')) {
                mod = fc;
                fc = *++p;
            }
            if (fc == '\0' || fc == '%') {
                if (plen > 1) {
                    char bad[256];
                    snprintf(bad, sizeof(bad), "%.*s%c", (int)plen, start, fc ? fc : '\0');
                    fflush(stdout);
                    fprintf(stderr, "stat: %s: invalid directive\n", gnuQuoteLocale(bad, q, sizeof(q)));
                    *fatal = 1;
                    return false;
                }
                putchar('%');
                b = fc ? p : p - 1;
                continue;
            }
            /* the 'I' flag is GNU's alone; printf must not see it */
            char clean[64];
            size_t cl = 0;
            for (const char *s = start; s < start + plen && cl < sizeof(clean) - 1; s++)
                if (*s != 'I') clean[cl++] = *s;
            clean[cl] = '\0';
            ok &= statDirective(t, clean, cl, mod, fc);
            b = p;
        } else if (*b == '\\' && escapes) {
            b++;
            if (*b == '\0') {
                fflush(stdout);
                fputs("stat: warning: backslash at end of format\n", stderr);
                putchar('\\');
                b--;
                continue;
            }
            if (*b >= '0' && *b <= '7') {
                int v = 0, k = 0;
                for (; k < 3 && *b >= '0' && *b <= '7'; k++, b++) v = v * 8 + (*b - '0');
                b--;
                putchar(v);
            } else if (*b == 'x' && isxdigit((unsigned char)b[1])) {
                int v = 0, k = 0;
                for (b++; k < 2 && isxdigit((unsigned char)*b); k++, b++)
                    v = v * 16 + (isdigit((unsigned char)*b) ? *b - '0' : (tolower((unsigned char)*b) - 'a' + 10));
                b--;
                putchar(v);
            } else {
                const char *from = "abefnrtv\"\\", *to = "\a\b\x1b\f\n\r\t\v\"\\";
                const char *hit = strchr(from, *b);
                if (hit) {
                    putchar(to[hit - from]);
                } else {
                    fflush(stdout);
                    fprintf(stderr, "stat: warning: unrecognized escape '\\%c'\n", *b);
                    putchar(*b);
                }
            }
        } else {
            putchar(*b);
        }
    }
    return ok;
}

static const GnuLongOpt statLongs[] = {
    {"dereference", GNU_NO_ARG, 'L'}, {"file-system", GNU_NO_ARG, 'f'}, {"format", GNU_REQ_ARG, 'c'},
    {"printf", GNU_REQ_ARG, 1},       {"terse", GNU_NO_ARG, 't'},       {"cached", GNU_REQ_ARG, 2},
    {"help", GNU_NO_ARG, 3},          {"version", GNU_NO_ARG, 4},
};

int smallclueStatCommand(int argc, char **argv) {
    GnuGetopt g;
    gnuGetoptInit(&g, argc, argv, "stat", "c:fLt", statLongs, sizeof(statLongs) / sizeof(statLongs[0]));
    const char *format = NULL;
    bool escapes = false, newline = true, deref = false, fs = false, terse = false;
    int status = 1, c;
    char q[PATH_MAX + 64];
    while ((c = gnuGetopt(&g)) != -1) {
        switch (c) {
        case 'c': format = g.arg; escapes = false; newline = true; break;
        case 1: format = g.arg; escapes = true; newline = false; break;
        case 'f': fs = true; break;
        case 'L': deref = true; break;
        case 't': terse = true; break;
        case 2:
            if (strcmp(g.arg, "always") && strcmp(g.arg, "never") && strcmp(g.arg, "default")) {
                char q2[64];
                fprintf(stderr, "stat: invalid argument %s for %s\nValid arguments are:\n  - 'default'\n"
                                "  - 'always'\n  - 'never'\n",
                        gnuQuoteLocale(g.arg, q, sizeof(q)), gnuQuoteLocale("--cached", q2, sizeof(q2)));
                goto try;
            }
            break;
        case 3:
            fputs("Usage: stat [OPTION]... FILE...\n"
                  "Display file or file system status.\n\n"
                  "Mandatory arguments to long options are mandatory for short options too.\n"
                  "  -L, --dereference     follow links\n"
                  "  -f, --file-system     display file system status instead of file status\n"
                  "      --cached=MODE     specify how to use cached attributes;\n"
                  "                          useful on remote file systems. See MODE below\n"
                  "  -c  --format=FORMAT   use the specified FORMAT instead of the default;\n"
                  "                          output a newline after each use of FORMAT\n"
                  "      --printf=FORMAT   like --format, but interpret backslash escapes,\n"
                  "                          and do not output a mandatory trailing newline;\n"
                  "                          if you want a newline, include \\n in FORMAT\n"
                  "  -t, --terse           print the information in terse form\n"
                  "      --help        display this help and exit\n"
                  "      --version     output version information and exit\n",
                  stdout);
            status = 0;
            goto done;
        case 4: puts("stat (SmallCLUE) 9.4"); status = 0; goto done;
        default: goto try;
        }
    }
    if (g.nops == 0) {
        fputs("stat: missing operand\n", stderr);
        goto try;
    }
    status = 0;
    for (int i = 0; i < g.nops; i++) {
        StatTarget t;
        memset(&t, 0, sizeof(t));
        t.name = g.ops[i];
        t.quoting = STAT_Q_LITERAL;
        if (format) {
            /* GNU's getenv_quoting_style: shell-escape-always unless QUOTING_STYLE says */
            const char *qs = getenv("QUOTING_STYLE");
            t.quoting = STAT_Q_ALWAYS;
            if (qs && !strcmp(qs, "literal")) t.quoting = STAT_Q_LITERAL;
            else if (qs && (!strcmp(qs, "shell") || !strcmp(qs, "shell-escape"))) t.quoting = STAT_Q_SHELL;
            else if (qs && (!strcmp(qs, "c") || !strcmp(qs, "escape") || !strcmp(qs, "c-maybe"))) t.quoting = STAT_Q_C;
        }
        t.fs = fs;
        t.deref = deref;
        bool isStdin = !strcmp(t.name, "-");
        if (fs) {
            if (isStdin) {
                fprintf(stderr, "stat: using %s to denote standard input does not work in file system mode\n",
                        gnuQuoteLocale("-", q, sizeof(q)));
                status = 1;
                continue;
            }
            if (statfs(t.name, &t.sfs) != 0 || statvfs(t.name, &t.svfs) != 0) {
                fprintf(stderr, "stat: cannot read file system information for %s: %s\n",
                        gnuQuote(t.name, q, sizeof(q)), strerror(errno));
                status = 1;
                continue;
            }
        } else {
            int rc = isStdin ? fstat(STDIN_FILENO, &t.st) : deref ? stat(t.name, &t.st) : lstat(t.name, &t.st);
            if (rc != 0) {
                fprintf(stderr, "stat: cannot statx %s: %s\n", gnuQuote(t.name, q, sizeof(q)), strerror(errno));
                status = 1;
                continue;
            }
        }
        const char *fmt = format;
        bool nl = format ? newline : false;
        bool esc = format ? escapes : false;
        char dflt[512];
        if (!fmt) {
            if (fs) {
                fmt = terse ? "%n %i %l %t %s %S %b %f %a %c %d\n"
                            : "  File: \"%n\"\n    ID: %-8i Namelen: %-7l Type: %T\n"
                              "Block size: %-10s Fundamental block size: %S\n"
                              "Blocks: Total: %-10b Free: %-10f Available: %a\n"
                              "Inodes: Total: %-10c Free: %d\n";
            } else if (terse) {
                fmt = "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o\n";
            } else {
                bool dev = S_ISBLK(t.st.st_mode) || S_ISCHR(t.st.st_mode);
                snprintf(dflt, sizeof(dflt),
                         "  File: %%N\n  Size: %%-10s\tBlocks: %%-10b IO Block: %%-6o %%F\n%s"
                         "Access: (%%04a/%%10.10A)  Uid: (%%5u/%%8U)   Gid: (%%5g/%%8G)\n"
                         "Access: %%x\nModify: %%y\nChange: %%z\n Birth: %%w\n",
                                         dev ? "Device: %Hd,%Ld\tInode: %-10i  Links: %-5h Device type: %Hr,%Lr\n"
                             : "Device: %Hd,%Ld\tInode: %-10i  Links: %h\n");
                fmt = dflt;
            }
        }
        int fatal = 0;
        if (!statPrint(&t, fmt, esc, &fatal)) status = 1;
        if (fatal) goto done;
        if (nl) putchar('\n');
    }
    goto done;
try:
    fputs("Try 'stat --help' for more information.\n", stderr);
    status = 1;
done:
    gnuGetoptFree(&g);
    if (fflush(stdout) != 0 && status == 0) {
        gnuWriteError("stat", errno);
        status = 1;
    }
    return status;
}
