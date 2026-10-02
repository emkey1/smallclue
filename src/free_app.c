/* free: memory in use, from /proc/meminfo, the way procps-ng 4's free reports
 * it -- same columns, same arithmetic, same units.
 *
 *   used        MemTotal - MemAvailable (procps 4; 3.3 subtracted free and
 *               cache instead, which over-reported on modern kernels)
 *   buff/cache  Buffers + Cached + SReclaimable
 *   shared      Shmem
 *
 * Units: KiB by default; -b -k -m -g --tera --peta scale by 1024 (or by 1000
 * with --si, which -h also honours), and the long --kibi..--pebi and
 * --kilo..--peta spellings say the base outright. -h picks a unit per value
 * the way procps' scale_size does: at most four characters, five with the i.
 */

#include "free_app.h"

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    unsigned long total, free, available, buffers, cached, reclaimable, shmem;
    unsigned long swapTotal, swapFree;
    unsigned long lowTotal, lowFree, highTotal, highFree;
    bool haveAvailable, haveLow;
} FreeMem;

static bool freeRead(FreeMem *m) {
    memset(m, 0, sizeof(*m));
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        return false;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[64];
        unsigned long value = 0;
        if (sscanf(line, "%63[^:]: %lu", key, &value) != 2) {
            continue;
        }
        if (!strcmp(key, "MemTotal")) m->total = value;
        else if (!strcmp(key, "MemFree")) m->free = value;
        else if (!strcmp(key, "MemAvailable")) { m->available = value; m->haveAvailable = true; }
        else if (!strcmp(key, "Buffers")) m->buffers = value;
        else if (!strcmp(key, "Cached")) m->cached = value;
        else if (!strcmp(key, "SReclaimable")) m->reclaimable = value;
        else if (!strcmp(key, "Shmem")) m->shmem = value;
        else if (!strcmp(key, "SwapTotal")) m->swapTotal = value;
        else if (!strcmp(key, "SwapFree")) m->swapFree = value;
        else if (!strcmp(key, "LowTotal")) { m->lowTotal = value; m->haveLow = true; }
        else if (!strcmp(key, "LowFree")) m->lowFree = value;
        else if (!strcmp(key, "HighTotal")) m->highTotal = value;
        else if (!strcmp(key, "HighFree")) m->highFree = value;
    }
    fclose(f);
    if (!m->haveLow) {
        /* No highmem split: everything is low, as procps reports it. */
        m->lowTotal = m->total;
        m->lowFree = m->free;
    }
    return true;
}

typedef struct {
    bool human, si, wide, total, lohi;
    int exponent;   /* 0 default (KiB), 1 bytes, 2 K, 3 M, 4 G, 5 T, 6 P */
} FreeOpts;

/* procps' scale_size, value in KiB. */
static const char *freeScale(unsigned long kib, const FreeOpts *o, char *buf, size_t size) {
    static const char up[] = { 'B', 'K', 'M', 'G', 'T', 'P', 0 };
    double base = o->si ? 1000.0 : 1024.0;
    long long bytes = (long long)kib * 1024LL;
    if (!o->human) {
        if (o->exponent == 0) {
            snprintf(buf, size, "%ld", (long)(bytes / (long long)base));
        } else if (o->exponent == 1) {
            snprintf(buf, size, "%lld", bytes);
        } else {
            snprintf(buf, size, "%ld", (long)(bytes / pow(base, o->exponent - 1)));
        }
        return buf;
    }
    if (snprintf(buf, size, "%lld%c", bytes, up[0]) <= 4) {
        return buf;
    }
    for (int i = 1; up[i]; i++) {
        double v = bytes / pow(base, i);
        if (o->si) {
            if (snprintf(buf, size, "%.1f%c", (float)v, up[i]) <= 4) return buf;
            if (snprintf(buf, size, "%ld%c", (long)v, up[i]) <= 4) return buf;
        } else {
            if (snprintf(buf, size, "%.1f%ci", (float)v, up[i]) <= 5) return buf;
            if (snprintf(buf, size, "%ld%ci", (long)v, up[i]) <= 5) return buf;
        }
    }
    return buf;
}

static void freeCol(unsigned long kib, const FreeOpts *o) {
    char buf[64];
    printf("%12s", freeScale(kib, o, buf, sizeof(buf)));
}

static void freeReport(const FreeMem *m, const FreeOpts *o) {
    unsigned long cache = m->cached + m->reclaimable;
    unsigned long available = m->haveAvailable ? m->available : m->free;
    unsigned long used = m->total >= available ? m->total - available : 0;
    if (!m->haveAvailable) {
        unsigned long busy = m->free + m->buffers + cache;
        used = m->total >= busy ? m->total - busy : 0;
    }
    unsigned long swapUsed = m->swapTotal >= m->swapFree ? m->swapTotal - m->swapFree : 0;

    if (o->wide) {
        printf("               total        used        free      shared     buffers       cache   available\n");
    } else {
        printf("               total        used        free      shared  buff/cache   available\n");
    }
    printf("%-8s", "Mem:");
    freeCol(m->total, o);
    freeCol(used, o);
    freeCol(m->free, o);
    freeCol(m->shmem, o);
    if (o->wide) {
        freeCol(m->buffers, o);
        freeCol(cache, o);
    } else {
        freeCol(m->buffers + cache, o);
    }
    freeCol(available, o);
    printf("\n");
    if (o->lohi) {
        printf("%-8s", "Low:");
        freeCol(m->lowTotal, o);
        freeCol(m->lowTotal - m->lowFree, o);
        freeCol(m->lowFree, o);
        printf("\n");
        printf("%-8s", "High:");
        freeCol(m->highTotal, o);
        freeCol(m->highTotal - m->highFree, o);
        freeCol(m->highFree, o);
        printf("\n");
    }
    printf("%-8s", "Swap:");
    freeCol(m->swapTotal, o);
    freeCol(swapUsed, o);
    freeCol(m->swapFree, o);
    printf("\n");
    if (o->total) {
        printf("%-8s", "Total:");
        freeCol(m->total + m->swapTotal, o);
        freeCol(used + swapUsed, o);
        freeCol(m->free + m->swapFree, o);
        printf("\n");
    }
}

static void freeUsage(FILE *out) {
    fprintf(out,
            "usage: free [options]\n"
            "  -b, -k, -m, -g, --tera, --peta   bytes, KiB (default), MiB, GiB, TiB, PiB\n"
            "  --kilo .. --peta, --kibi .. --pebi  the same, saying the base\n"
            "  -h, --human     the unit that fits each value; --si: powers of 1000\n"
            "  -w, --wide      buffers and cache in separate columns\n"
            "  -l, --lohi      low and high memory\n"
            "  -t, --total     a total of memory and swap\n"
            "  -s N, --seconds N   repeat every N seconds; -c N, --count N: N times\n");
}

int smallclueFreeCommand(int argc, char **argv) {
    FreeOpts o = {0};
    double seconds = 0;
    long count = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *value = NULL;
        if (!strcmp(a, "-b") || !strcmp(a, "--bytes")) o.exponent = 1;
        else if (!strcmp(a, "-k") || !strcmp(a, "--kibi")) o.exponent = 2;
        else if (!strcmp(a, "-m") || !strcmp(a, "--mebi")) o.exponent = 3;
        else if (!strcmp(a, "-g") || !strcmp(a, "--gibi")) o.exponent = 4;
        else if (!strcmp(a, "--tera") || !strcmp(a, "--tebi")) { o.exponent = 5; if (!strcmp(a, "--tera")) o.si = true; }
        else if (!strcmp(a, "--peta") || !strcmp(a, "--pebi")) { o.exponent = 6; if (!strcmp(a, "--peta")) o.si = true; }
        else if (!strcmp(a, "--kilo")) { o.exponent = 2; o.si = true; }
        else if (!strcmp(a, "--mega")) { o.exponent = 3; o.si = true; }
        else if (!strcmp(a, "--giga")) { o.exponent = 4; o.si = true; }
        else if (!strcmp(a, "-h") || !strcmp(a, "--human")) o.human = true;
        else if (!strcmp(a, "--si")) o.si = true;
        else if (!strcmp(a, "-w") || !strcmp(a, "--wide")) o.wide = true;
        else if (!strcmp(a, "-t") || !strcmp(a, "--total")) o.total = true;
        else if (!strcmp(a, "-l") || !strcmp(a, "--lohi")) o.lohi = true;
        else if (!strcmp(a, "-s") || !strcmp(a, "--seconds") ||
                 !strcmp(a, "-c") || !strcmp(a, "--count")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "free: option '%s' requires an argument\n", a);
                freeUsage(stderr);
                return 1;
            }
            value = argv[++i];
            char *end = NULL;
            if (a[1] == 's' || !strcmp(a, "--seconds")) {
                seconds = strtod(value, &end);
                if (!end || *end || seconds <= 0) {
                    fprintf(stderr, "free: seconds argument '%s' is not positive number\n", value);
                    return 1;
                }
            } else {
                count = strtol(value, &end, 10);
                if (!end || *end || count < 1) {
                    fprintf(stderr, "free: failed to parse count argument: '%s'\n", value);
                    return 1;
                }
            }
        } else if (!strcmp(a, "--help")) {
            freeUsage(stdout);
            return 0;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("free (smallclue)\n");
            return 0;
        } else {
            fprintf(stderr, "free: invalid option -- '%s'\n", a);
            freeUsage(stderr);
            return 1;
        }
    }
    if (count > 0 && seconds <= 0) {
        seconds = 1;
    }
    for (long n = 0;; n++) {
        FreeMem m;
        if (!freeRead(&m)) {
            fprintf(stderr, "free: cannot read /proc/meminfo: %s\n", strerror(errno));
            return 1;
        }
        freeReport(&m, &o);
        fflush(stdout);
        if (seconds <= 0 || (count > 0 && n + 1 >= count)) {
            break;
        }
        printf("\n");
        fflush(stdout);
        usleep((useconds_t)(seconds * 1000000.0));
    }
    return 0;
}
