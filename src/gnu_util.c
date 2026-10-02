/*
 * The shared GNU-compatible helpers declared in gnu_*.h, compiled once.
 * They were header-only statics: every applet that used one carried its
 * own copy (gnuQuoteLocale alone 21 times).
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gnu_util.h"
#include "gnu_getopt.h"
#include "gnu_size.h"
#include "gnu_regex.h"
#include "gnu_mode.h"
#include "gnu_backup.h"

/* --- gnu_util.h --- */

const char *gnuQuote(const char *s, char *buf, size_t size) {
    bool hasSingle = strchr(s, '\'') != NULL;
    bool doubleOk = hasSingle && !strpbrk(s, "\"$`\\!");
    size_t o = 0;
#define GNU_PUT(c) do { if (o + 1 < size) buf[o++] = (c); } while (0)
    if (doubleOk) {
        GNU_PUT('"');
        for (const char *p = s; *p; p++) GNU_PUT(*p);
        GNU_PUT('"');
    } else {
        GNU_PUT('\'');
        for (const char *p = s; *p; p++) {
            if (*p == '\'') {
                GNU_PUT('\''); GNU_PUT('\\'); GNU_PUT('\''); GNU_PUT('\'');
            } else {
                GNU_PUT(*p);
            }
        }
        GNU_PUT('\'');
    }
#undef GNU_PUT
    buf[o] = '\0';
    return buf;
}

const char *gnuQuoteMaybe(const char *s, char *buf, size_t size) {
    bool plain = *s != '\0';
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || strchr("+-./:=@_%^,", c) || c >= 0x80)) {
            plain = false;
            break;
        }
    }
    if (!plain) return gnuQuote(s, buf, size);
    snprintf(buf, size, "%s", s);
    return buf;
}

bool gnuUtf8Locale(void) {
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_CTYPE");
    if (!v || !*v) v = getenv("LANG");
    if (!v) return false;
    return strstr(v, "UTF-8") || strstr(v, "utf8") || strstr(v, "UTF8") || strstr(v, "utf-8");
}

const char *gnuQuoteLocaleAs(bool utf8, const char *s, char *buf, size_t size) {
    const char *lq = utf8 ? "\xe2\x80\x98" : "'", *rq = utf8 ? "\xe2\x80\x99" : "'";
    size_t rql = strlen(rq), o = 0;
#define GNU_QPUT(str, n) do { size_t n_ = (n); if (o + n_ < size) { memcpy(buf + o, (str), n_); o += n_; } } while (0)
    GNU_QPUT(lq, strlen(lq));
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        static const char named[] = "\a\b\f\n\r\t\v";
        static const char letters[] = "abfnrtv";
        const char *hit = *p ? memchr(named, *p, 7) : NULL;
        if (!strncmp((const char *)p, rq, rql)) {
            GNU_QPUT("\\", 1);
            GNU_QPUT(p, rql);
            p += rql - 1;
        } else if (*p == '\\') {
            GNU_QPUT("\\\\", 2);
        } else if (hit) {
            char e[2] = {'\\', letters[hit - named]};
            GNU_QPUT(e, 2);
        } else if (*p < 0x20 || *p == 0x7f || (*p >= 0x80 && !utf8)) {
            char e[5];
            snprintf(e, sizeof(e), "\\%03o", *p);
            GNU_QPUT(e, 4);
        } else {
            GNU_QPUT(p, 1);
        }
    }
    GNU_QPUT(rq, rql);
#undef GNU_QPUT
    buf[o < size ? o : size - 1] = '\0';
    return buf;
}

void gnuWriteError(const char *prog, int err) {
    if (err == EPIPE) {
        struct sigaction sa;
        if (sigaction(SIGPIPE, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL) return;
    }
    fprintf(stderr, "%s: write error: %s\n", prog, strerror(err));
}

bool gnuYes(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return false;
    return line[0] == 'y' || line[0] == 'Y';
}

bool gnuBufPut(GnuBuf *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->n + n + 1) cap *= 2;
        char *v = (char *)realloc(b->s, cap);
        if (!v) return false;
        b->s = v;
        b->cap = cap;
    }
    memcpy(b->s + b->n, s, n);
    b->n += n;
    b->s[b->n] = '\0';
    return true;
}

bool gnuWriteAll(int fd, const void *buf, size_t n) {
    const unsigned char *p = (const unsigned char *)buf;
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

char *gnuPathJoin(const char *dir, const char *name) {
    size_t dl = strlen(dir), nl = strlen(name);
    char *p = (char *)malloc(dl + nl + 2);
    if (!p) return NULL;
    memcpy(p, dir, dl);
    if (dl && dir[dl - 1] != '/') p[dl++] = '/';
    memcpy(p + dl, name, nl + 1);
    return p;
}

static int gnuVerOrder(const char *s, size_t pos, size_t len) {
    if (pos == len) return -1;
    unsigned char c = (unsigned char)s[pos];
    if (isdigit(c)) return 0;
    if (isalpha(c)) return c;
    if (c == '~') return -2;
    return c + UCHAR_MAX + 1;
}

static int gnuVerRevCmp(const char *a, size_t al, const char *b, size_t bl) {
    size_t i = 0, j = 0;
    while (i < al || j < bl) {
        int firstDiff = 0;
        while ((i < al && !isdigit((unsigned char)a[i])) || (j < bl && !isdigit((unsigned char)b[j]))) {
            int ac = gnuVerOrder(a, i, al), bc = gnuVerOrder(b, j, bl);
            if (ac != bc) return ac - bc;
            i++;
            j++;
        }
        while (i < al && a[i] == '0') i++;
        while (j < bl && b[j] == '0') j++;
        while (i < al && j < bl && isdigit((unsigned char)a[i]) && isdigit((unsigned char)b[j])) {
            if (!firstDiff) firstDiff = (unsigned char)a[i] - (unsigned char)b[j];
            i++;
            j++;
        }
        if (i < al && isdigit((unsigned char)a[i])) return 1;
        if (j < bl && isdigit((unsigned char)b[j])) return -1;
        if (firstDiff) return firstDiff;
    }
    return 0;
}

/* Length without the trailing run of (\.[A-Za-z~][A-Za-z0-9~]*)* suffixes. */
static size_t gnuVerPrefix(const char *s, size_t n) {
    size_t prefix = 0;
    for (size_t i = 0;;) {
        if (i == n) return prefix;
        i++;
        prefix = i;
        while (i + 1 < n && s[i] == '.' && (isalpha((unsigned char)s[i + 1]) || s[i + 1] == '~'))
            for (i += 2; i < n && (isalnum((unsigned char)s[i]) || s[i] == '~'); i++) {}
    }
}

int gnuFilevercmp(const char *a, size_t al, const char *b, size_t bl) {
    if (al == 0) return -(bl != 0);
    if (bl == 0) return 1;
    if (a[0] == '.') {
        if (b[0] != '.') return -1;
        bool adot = al == 1, bdot = bl == 1;
        if (adot) return -!bdot;
        if (bdot) return 1;
        bool add = a[1] == '.' && al == 2, bdd = b[1] == '.' && bl == 2;
        if (add) return -!bdd;
        if (bdd) return 1;
    } else if (b[0] == '.') {
        return 1;
    }
    size_t ap = gnuVerPrefix(a, al), bp = gnuVerPrefix(b, bl);
    int r = gnuVerRevCmp(a, ap, b, bp);
    return r || (ap == al && bp == bl) ? r : gnuVerRevCmp(a, al, b, bl);
}

/* --- gnu_getopt.h --- */

void gnuGetoptInit(GnuGetopt *g, int argc, char **argv, const char *prog, const char *shorts,
                                 const GnuLongOpt *longs, size_t nlongs) {
    memset(g, 0, sizeof(*g));
    g->argc = argc;
    g->argv = argv;
    g->prog = prog;
    g->shorts = shorts;
    g->longs = longs;
    g->nlongs = nlongs;
    g->ind = 1;
    g->ops = (char **)calloc((size_t)argc + 1, sizeof(char *));
}

int gnuGetoptLong(GnuGetopt *g, const char *body) {
    const char *eq = strchr(body, '=');
    size_t len = eq ? (size_t)(eq - body) : strlen(body);
    const GnuLongOpt *found = NULL;
    bool ambiguous = false;
    for (size_t i = 0; i < g->nlongs; i++) {
        const GnuLongOpt *o = &g->longs[i];
        if (strncmp(o->name, body, len)) continue;
        if (strlen(o->name) == len) {
            found = o;
            ambiguous = false;
            break;
        }
        if (!found) found = o;
        else if (found->hasArg != o->hasArg || found->val != o->val) ambiguous = true;
    }
    if (ambiguous) {
        fprintf(stderr, "%s: option '--%s' is ambiguous; possibilities:", g->prog, body);
        for (size_t i = 0; i < g->nlongs; i++)
            if (!strncmp(g->longs[i].name, body, len)) fprintf(stderr, " '--%s'", g->longs[i].name);
        fputc('\n', stderr);
        return '?';
    }
    if (!found) {
        fprintf(stderr, "%s: unrecognized option '--%s'\n", g->prog, body);
        return '?';
    }
    g->arg = NULL;
    if (eq) {
        if (found->hasArg == GNU_NO_ARG) {
            fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n", g->prog, found->name);
            return '?';
        }
        g->arg = eq + 1;
    } else if (found->hasArg == GNU_REQ_ARG) {
        if (g->ind >= g->argc) {
            fprintf(stderr, "%s: option '--%s' requires an argument\n", g->prog, found->name);
            return '?';
        }
        g->arg = g->argv[g->ind++];
    }
    return found->val;
}

int gnuGetopt(GnuGetopt *g) {
    g->arg = NULL;
    if (!g->cluster) {
        for (;;) {
            if (g->ind >= g->argc) return -1;
            char *a = g->argv[g->ind++];
            if (g->done || a[0] != '-' || a[1] == '\0') {
                if (g->inOrder) {
                    g->arg = a;
                    return 1;
                }
                g->ops[g->nops++] = a;
                if (g->shorts[0] == '+' || getenv("POSIXLY_CORRECT")) g->done = true;
                continue;
            }
            if (!strcmp(a, "--")) {
                g->done = true;
                continue;
            }
            if (a[1] == '-') return gnuGetoptLong(g, a + 2);
            g->cluster = a + 1;
            break;
        }
    }
    char c = *g->cluster++;
    const char *spec = c != ':' && c != '+' ? strchr(g->shorts, c) : NULL;
    if (!spec) {
        fprintf(stderr, "%s: invalid option -- '%c'\n", g->prog, c);
        if (!*g->cluster) g->cluster = NULL;
        return '?';
    }
    if (spec[1] == ':') {
        if (*g->cluster) {
            g->arg = g->cluster;
        } else if (spec[2] == ':') {
            g->arg = NULL;    /* optional: only when attached */
        } else if (g->ind < g->argc) {
            g->arg = g->argv[g->ind++];
        } else {
            fprintf(stderr, "%s: option requires an argument -- '%c'\n", g->prog, c);
            g->cluster = NULL;
            return '?';
        }
        g->cluster = NULL;
    } else if (!*g->cluster) {
        g->cluster = NULL;
    }
    return (unsigned char)c;
}

/* --- gnu_size.h --- */

int gnuParseSize(const char *s, uintmax_t *out) {
    if (*s == '+') s++;
    if (!isdigit((unsigned char)*s)) return 1;
    char *end;
    errno = 0;
    uintmax_t v = strtoumax(s, &end, 10);
    bool overflow = errno == ERANGE;
    if (*end == '\0') {
        if (overflow) return 2;
        *out = v;
        return 0;
    }
    static const char powers[] = "KMGTPEZYRQ";
    uintmax_t mult = 1;
    char u = *end;
    const char *rest = end + 1;
    if (u == 'b') {
        mult = 512;
    } else {
        char up = u == 'k' ? 'K' : u == 'm' ? 'M' : u;
        const char *pos = up ? strchr(powers, up) : NULL;
        if (!pos) return 1;
        unsigned base = 1024;
        if (!strcmp(rest, "B") || !strcmp(rest, "D")) {
            base = 1000;
            rest++;
        } else if (!strcmp(rest, "iB")) {
            rest += 2;
        }
        for (int i = 0; i <= (int)(pos - powers); i++) {
            if (mult > UINTMAX_MAX / base) return 2;
            mult *= base;
        }
    }
    if (*rest != '\0') return 1;
    if (overflow || (v != 0 && mult > UINTMAX_MAX / v)) return 2;
    *out = v * mult;
    return 0;
}

/* --- gnu_regex.h --- */

int gnuRegexFlags(int flags) {
#ifdef REG_ENHANCED
    flags |= REG_ENHANCED;
#endif
    return flags;
}

const char *gnuRegexMessage(int code) {
    switch (code) {
    case REG_EPAREN: return "Unmatched ( or \\(";
    case REG_EBRACK: return "Unmatched [, [^, [:, [., or [=";
    case REG_EBRACE: return "Unmatched \\{";
    case REG_BADBR: return "Invalid content of \\{\\}";
    case REG_BADRPT: return "Invalid preceding regular expression";
    case REG_EESCAPE: return "Trailing backslash";
    case REG_ERANGE: return "Invalid range end";
    case REG_ECTYPE: return "Invalid character class name";
    case REG_ESUBREG: return "Invalid back reference";
    case REG_ECOLLATE: return "Invalid collation character";
    case REG_ESPACE: return "Memory exhausted";
    default: return "Invalid regular expression";
    }
}

/* --- gnu_mode.h --- */

bool gnuModeCompile(const char *s, GnuMode *out) {
    out->v = NULL;
    out->n = 0;
    if (*s >= '0' && *s <= '7') {
        mode_t octal = 0;
        const char *p = s;
        for (; *p >= '0' && *p <= '7'; p++) {
            octal = octal * 8 + (mode_t)(*p - '0');
            if (octal > 07777) return false;
        }
        if (*p) return false;
        out->v = (GnuModeChange *)calloc(1, sizeof(GnuModeChange));
        if (!out->v) return false;
        out->v[0].op = '=';
        out->v[0].flag = GNU_MODE_ORDINARY;
        out->v[0].affected = GNU_MODE_BITS;
        out->v[0].value = octal;
        /* Fewer than five digits leave a directory's set-ID bits alone. */
        out->v[0].mentioned = p - s < 5 ? (octal & (S_ISUID | S_ISGID)) | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
                                        : GNU_MODE_BITS;
        out->n = 1;
        return true;
    }
    size_t cap = 0;
    const char *p = s;
    for (;;) {
        mode_t affected = 0;
        for (;; p++) {
            if (*p == 'u') affected |= S_ISUID | S_IRWXU;
            else if (*p == 'g') affected |= S_ISGID | S_IRWXG;
            else if (*p == 'o') affected |= S_ISVTX | S_IRWXO;
            else if (*p == 'a') affected |= GNU_MODE_BITS;
            else break;
        }
        if (*p != '=' && *p != '+' && *p != '-') goto invalid;
        do {
            char op = *p++;
            mode_t value = 0;
            char flag = GNU_MODE_ORDINARY;
            bool octal = false;
            mode_t who = affected;
            if (*p >= '0' && *p <= '7') {
                /* [-+=]OCTAL: every mode bit, and no "who" allowed. */
                if (affected) goto invalid;
                for (; *p >= '0' && *p <= '7'; p++) {
                    value = value * 8 + (mode_t)(*p - '0');
                    if (value > 07777) goto invalid;
                }
                if (*p && *p != ',') goto invalid;
                who = GNU_MODE_BITS;
                octal = true;
            } else if (*p == 'u' || *p == 'g' || *p == 'o') {
                value = *p == 'u' ? S_IRWXU : *p == 'g' ? S_IRWXG : S_IRWXO;
                flag = GNU_MODE_COPY_EXISTING;
                p++;
            } else {
                for (;; p++) {
                    if (*p == 'r') value |= S_IRUSR | S_IRGRP | S_IROTH;
                    else if (*p == 'w') value |= S_IWUSR | S_IWGRP | S_IWOTH;
                    else if (*p == 'x') value |= S_IXUSR | S_IXGRP | S_IXOTH;
                    else if (*p == 'X') flag = GNU_MODE_X_IF_ANY_X;
                    else if (*p == 's') value |= S_ISUID | S_ISGID;
                    else if (*p == 't') value |= S_ISVTX;
                    else break;
                }
            }
            if (out->n == cap) {
                cap = cap ? cap * 2 : 4;
                GnuModeChange *v = (GnuModeChange *)realloc(out->v, cap * sizeof(GnuModeChange));
                if (!v) goto invalid;
                out->v = v;
            }
            GnuModeChange *c = &out->v[out->n++];
            c->op = op;
            c->flag = flag;
            c->affected = who;
            c->value = value;
            c->mentioned = octal ? GNU_MODE_BITS : who ? who & value : value;
        } while (*p == '=' || *p == '+' || *p == '-');
        if (*p != ',') break;
        p++;
    }
    if (*p == '\0') return true;
invalid:
    gnuModeFree(out);
    return false;
}

mode_t gnuModeAdjust(mode_t old, bool dir, mode_t umaskValue, const GnuMode *m, mode_t *changedBits) {
    mode_t newmode = old & GNU_MODE_BITS;
    mode_t bits = 0;
    for (size_t i = 0; i < m->n; i++) {
        const GnuModeChange *c = &m->v[i];
        mode_t affected = c->affected;
        mode_t omit = (dir ? S_ISUID | S_ISGID : 0) & ~c->mentioned;
        mode_t value = c->value;
        if (c->flag == GNU_MODE_COPY_EXISTING) {
            value &= newmode;
            value |= ((value & (S_IRUSR | S_IRGRP | S_IROTH) ? S_IRUSR | S_IRGRP | S_IROTH : 0) |
                      (value & (S_IWUSR | S_IWGRP | S_IWOTH) ? S_IWUSR | S_IWGRP | S_IWOTH : 0) |
                      (value & (S_IXUSR | S_IXGRP | S_IXOTH) ? S_IXUSR | S_IXGRP | S_IXOTH : 0));
        } else if (c->flag == GNU_MODE_X_IF_ANY_X) {
            if ((newmode & (S_IXUSR | S_IXGRP | S_IXOTH)) || dir) value |= S_IXUSR | S_IXGRP | S_IXOTH;
        }
        value &= (affected ? affected : ~umaskValue) & ~omit;
        if (c->op == '=') {
            mode_t preserved = (affected ? ~affected : 0) | omit;
            bits |= GNU_MODE_BITS & ~preserved;
            newmode = (newmode & preserved) | value;
        } else if (c->op == '+') {
            bits |= value;
            newmode |= value;
        } else {
            bits |= value;
            newmode &= ~value;
        }
    }
    if (changedBits) *changedBits = bits;
    return newmode;
}

void gnuModeString(mode_t m, char out[10]) {
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) out[i] = (m & (0400 >> i)) ? rwx[i] : '-';
    if (m & S_ISUID) out[2] = (m & S_IXUSR) ? 's' : 'S';
    if (m & S_ISGID) out[5] = (m & S_IXGRP) ? 's' : 'S';
    if (m & S_ISVTX) out[8] = (m & S_IXOTH) ? 't' : 'T';
    out[9] = '\0';
}

/* --- gnu_backup.h --- */

bool gnuBackupParse(const char *s, GnuBackup *out) {
    if (!s || !*s) { *out = GNU_BACKUP_EXISTING; return true; }
    static const struct { const char *name; GnuBackup kind; } names[] = {
        {"none", GNU_BACKUP_NONE}, {"off", GNU_BACKUP_NONE},
        {"simple", GNU_BACKUP_SIMPLE}, {"never", GNU_BACKUP_SIMPLE},
        {"existing", GNU_BACKUP_EXISTING}, {"nil", GNU_BACKUP_EXISTING},
        {"numbered", GNU_BACKUP_NUMBERED}, {"t", GNU_BACKUP_NUMBERED},
    };
    /* Unambiguous abbreviations are accepted, as argmatch does. */
    int found = -1;
    size_t len = strlen(s);
    for (int i = 0; i < 8; i++) {
        if (!strcmp(s, names[i].name)) { *out = names[i].kind; return true; }
        if (!strncmp(s, names[i].name, len)) {
            if (found >= 0 && names[found].kind != names[i].kind) return false;
            found = i;
        }
    }
    if (found < 0) return false;
    *out = names[found].kind;
    return true;
}

void gnuBackupComplain(const char *prog, const char *val) {
    char q[512];
    char q2[64];
    fprintf(stderr, "%s: invalid argument %s for %s\nValid arguments are:\n", prog,
            gnuQuoteLocale(val, q, sizeof(q)), gnuQuoteLocale("backup type", q2, sizeof(q2)));
    static const char *const rows[][2] = {{"none", "off"}, {"simple", "never"}, {"existing", "nil"}, {"numbered", "t"}};
    for (int i = 0; i < 4; i++) {
        char a[32], b[32];
        fprintf(stderr, "  - %s, %s\n", gnuQuoteLocale(rows[i][0], a, sizeof(a)), gnuQuoteLocale(rows[i][1], b, sizeof(b)));
    }
}

long gnuBackupHighest(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    char dir[4096];
    if (!slash) snprintf(dir, sizeof(dir), ".");
    else if (slash == path) snprintf(dir, sizeof(dir), "/");
    else snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
    DIR *d = opendir(dir);
    if (!d) return 0;
    long highest = 0;
    size_t blen = strlen(base);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *n = e->d_name;
        if (strncmp(n, base, blen) || strncmp(n + blen, ".~", 2)) continue;
        char *end = NULL;
        long v = strtol(n + blen + 2, &end, 10);
        if (end && end != n + blen + 2 && end[0] == '~' && end[1] == '\0' && v > highest) highest = v;
    }
    closedir(d);
    return highest;
}

bool gnuBackupName(GnuBackup kind, const char *suffix, const char *path, char *out, size_t size) {
    long highest = 0;
    if (kind == GNU_BACKUP_NUMBERED || kind == GNU_BACKUP_EXISTING) {
        highest = gnuBackupHighest(path);
        if (kind == GNU_BACKUP_EXISTING) kind = highest > 0 ? GNU_BACKUP_NUMBERED : GNU_BACKUP_SIMPLE;
    }
    int n = kind == GNU_BACKUP_NUMBERED ? snprintf(out, size, "%s.~%ld~", path, highest + 1)
                                        : snprintf(out, size, "%s%s", path, suffix);
    return n >= 0 && (size_t)n < size;
}

const char *gnuBackupSuffix(const char *given) {
    if (given) return given;
    const char *env = getenv("SIMPLE_BACKUP_SUFFIX");
    return env && *env && !strchr(env, '/') ? env : "~";
}
