/* ifconfig: net-tools' ifconfig, for showing interfaces -- same layout, words
 * and exit statuses as net-tools 2.10 on Linux.
 *
 *   ifconfig [-a] [-s] [IFACE]
 *
 * The interfaces come from the same snapshot ip reads (pscal-core's in the PSCAL
 * app, SmallCLUE's net_snapshot.c everywhere else). The counters come from
 * /proc/net/dev where there is one, as net-tools reads them, so overruns, frame,
 * carrier and TX drops are the kernel's and not zeros. Nothing here can
 * configure an interface: every change is refused the way Linux refuses an
 * unprivileged user, "SIOCSIFFLAGS: Operation not permitted", status 255 --
 * as ip refuses with RTNETLINK's message. */

#include "ifconfig_app.h"

#include "common/net_snapshot.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#if defined(__linux__)
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/* Linux's IFF_* values, which ifconfig prints as a number. On Darwin (and so in
 * AOK-iSH's native programs) several differ -- IFF_MULTICAST is 0x8000 there --
 * so each host flag is translated by name rather than printed raw. */
typedef struct {
    unsigned host;
    unsigned linux_value;
    const char *word;
} IfcFlag;

static const IfcFlag kIfcFlags[] = {
    {IFF_UP, 0x1, "UP"},
    {IFF_BROADCAST, 0x2, "BROADCAST"},
    {IFF_DEBUG, 0x4, "DEBUG"},
    {IFF_LOOPBACK, 0x8, "LOOPBACK"},
    {IFF_POINTOPOINT, 0x10, "POINTOPOINT"},
    {IFF_NOTRAILERS, 0x20, "NOTRAILERS"},
    {IFF_RUNNING, 0x40, "RUNNING"},
    {IFF_NOARP, 0x80, "NOARP"},
    {IFF_PROMISC, 0x100, "PROMISC"},
    {IFF_ALLMULTI, 0x200, "ALLMULTI"},
#if defined(IFF_MASTER)
    {IFF_MASTER, 0x400, "MASTER"},
#endif
#if defined(IFF_SLAVE)
    {IFF_SLAVE, 0x800, "SLAVE"},
#endif
    {IFF_MULTICAST, 0x1000, "MULTICAST"},
#if defined(IFF_PORTSEL)
    {IFF_PORTSEL, 0x2000, "PORTSEL"},
#endif
#if defined(IFF_AUTOMEDIA)
    {IFF_AUTOMEDIA, 0x4000, "AUTOMEDIA"},
#endif
#if defined(IFF_DYNAMIC)
    {IFF_DYNAMIC, 0x8000, "DYNAMIC"},
#endif
};

typedef struct {
    bool found;
    unsigned long long rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame;
    unsigned long long tx_bytes, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier;
} IfcCounters;

static unsigned ifcLinuxFlags(unsigned host) {
    unsigned out = 0;
    for (size_t i = 0; i < sizeof(kIfcFlags) / sizeof(kIfcFlags[0]); ++i) {
        if (host & kIfcFlags[i].host) {
            out |= kIfcFlags[i].linux_value;
        }
    }
    return out;
}

static bool ifcHas(unsigned linux_flags, unsigned value) {
    return (linux_flags & value) != 0;
}

/* /proc/net/dev's line for one interface: "name: rx bytes packets errs drop fifo
 * frame compressed multicast | tx bytes packets errs drop fifo colls carrier
 * compressed". */
static IfcCounters ifcReadCounters(const PscalNetLink *link) {
    IfcCounters c;
    memset(&c, 0, sizeof(c));
    FILE *f = fopen("/proc/net/dev", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char *colon = strchr(line, ':');
            if (!colon) {
                continue;
            }
            *colon = '\0';
            char *name = line;
            while (*name == ' ' || *name == '\t') {
                name++;
            }
            if (strcmp(name, link->name) != 0 && strcmp(name, link->host_name) != 0) {
                continue;
            }
            unsigned long long compressed, multicast;
            if (sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &c.rx_bytes, &c.rx_packets, &c.rx_errs, &c.rx_drop, &c.rx_fifo, &c.rx_frame, &compressed,
                       &multicast, &c.tx_bytes, &c.tx_packets, &c.tx_errs, &c.tx_drop, &c.tx_fifo, &c.tx_colls,
                       &c.tx_carrier) == 15) {
                c.found = true;
            }
            break;
        }
        fclose(f);
    }
    if (!c.found) {
        c.rx_bytes = link->rx_bytes;
        c.rx_packets = link->rx_packets;
        c.rx_errs = link->rx_errors;
        c.rx_drop = link->rx_dropped;
        c.tx_bytes = link->tx_bytes;
        c.tx_packets = link->tx_packets;
        c.tx_errs = link->tx_errors;
        c.tx_colls = link->tx_collisions;
    }
    return c;
}

/* txqueuelen is a Linux queue setting with no counterpart elsewhere. Where the
 * kernel can't say, 1000 is Linux's default for every device type here, and the
 * answer AOK-iSH's own kernel gives net-tools in a guest. */
static int ifcTxQueueLen(const PscalNetLink *link) {
#if defined(__linux__) && defined(SIOCGIFTXQLEN)
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct ifreq req;
        memset(&req, 0, sizeof(req));
        /* Interface names are IFNAMSIZ - 1 at most; a longer one is not a device. */
        snprintf(req.ifr_name, sizeof(req.ifr_name), "%.*s", (int)sizeof(req.ifr_name) - 1, link->host_name);
        int ok = ioctl(fd, SIOCGIFTXQLEN, &req);
        close(fd);
        if (ok == 0) {
            return req.ifr_qlen;
        }
    }
#else
    (void)link;
#endif
    return 1000;
}

/* net-tools' print_bytes_scaled: up to four divisions by 1024, the tenth taken
 * from the remainder of the last one and truncated, not rounded. */
static void ifcPrintBytes(FILE *out, unsigned long long bytes) {
    static const char *kUnits[] = {"", "Ki", "Mi", "Gi", "Ti"};
    unsigned long long whole = bytes;
    unsigned long tenth = 0;
    int unit = 0;
    for (int i = 0; i < 4; ++i) {
        if (whole >= 1024) {
            tenth = (unsigned long)((((unsigned)whole) & (1024 - 1)) * 10 / 1024);
            whole /= 1024;
            unit++;
        }
    }
    fprintf(out, "%llu.%lu %sB", whole, tenth, kUnits[unit]);
}

static void ifcFormatV4(const unsigned char *a, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static void ifcPrintLong(FILE *out, const PscalNetLink *link) {
    unsigned flags = ifcLinuxFlags(link->flags);
    fprintf(out, "%s: flags=%u<", link->name, flags);
    bool first = true;
    for (size_t i = 0; i < sizeof(kIfcFlags) / sizeof(kIfcFlags[0]); ++i) {
        if (link->flags & kIfcFlags[i].host) {
            fprintf(out, "%s%s", first ? "" : ",", kIfcFlags[i].word);
            first = false;
        }
    }
    fprintf(out, ">  mtu %u\n", link->mtu);

    /* net-tools asks SIOCGIFADDR, which answers with the first IPv4 address. */
    for (size_t i = 0; i < link->addr_count; ++i) {
        const PscalNetAddress *a = &link->addrs[i];
        if (a->family != AF_INET) {
            continue;
        }
        char addr[16], mask[16], other[16];
        unsigned char m[4] = {0};
        for (int b = 0; b < a->prefixlen && b < 32; ++b) {
            m[b / 8] |= (unsigned char)(0x80 >> (b % 8));
        }
        ifcFormatV4(a->addr, addr, sizeof(addr));
        ifcFormatV4(m, mask, sizeof(mask));
        fprintf(out, "        inet %s  netmask %s", addr, mask);
        if (ifcHas(flags, 0x10)) {
            /* The snapshot drops a peer equal to the address, as iproute2 does;
             * net-tools prints the destination regardless. */
            ifcFormatV4(a->has_peer ? a->peer : a->addr, other, sizeof(other));
            fprintf(out, "  destination %s", other);
        }
        if (ifcHas(flags, 0x2) && a->has_broadcast) {
            ifcFormatV4(a->broadcast, other, sizeof(other));
            fprintf(out, "  broadcast %s", other);
        }
        fputc('\n', out);
        break;
    }
    for (size_t i = 0; i < link->addr_count; ++i) {
        const PscalNetAddress *a = &link->addrs[i];
        if (a->family != AF_INET6) {
            continue;
        }
        char addr[INET6_ADDRSTRLEN];
        struct in6_addr in6;
        memcpy(&in6, a->addr, 16);
        if (!inet_ntop(AF_INET6, &in6, addr, sizeof(addr))) {
            continue;
        }
        const char *scope = pscalNetAddressScope(AF_INET6, a->addr);
        unsigned bits = strcmp(scope, "host") == 0 ? 0x10 : strcmp(scope, "link") == 0 ? 0x20
                      : strcmp(scope, "site") == 0 ? 0x40 : 0x0;
        fprintf(out, "        inet6 %s  prefixlen %d  scopeid 0x%x<%s>\n", addr, a->prefixlen, bits,
                strcmp(scope, "global") == 0 ? "global" : scope);
    }

    int qlen = ifcTxQueueLen(link);
    const char *type = pscalNetLinkType(link);
    if (ifcHas(flags, 0x8)) {
        fprintf(out, "        loop  txqueuelen %d  (Local Loopback)\n", qlen);
    } else if (strcmp(type, "ppp") == 0) {
        fprintf(out, "        ppp  txqueuelen %d  (Point-to-Point Protocol)\n", qlen);
    } else if (strcmp(type, "ether") == 0
#if !defined(__linux__)
               /* Darwin has no ARPHRD_NONE to say "no link layer": a tunnel just
                * has no address, and AOK-iSH's kernel calls it Ethernet. */
               || link->hwaddr_len == 0
#endif
    ) {
        unsigned char hw[6] = {0};
        if (link->hwaddr_len == 6) {
            memcpy(hw, link->hwaddr, 6);
        }
        fprintf(out, "        ether %02x:%02x:%02x:%02x:%02x:%02x  txqueuelen %d  (Ethernet)\n", hw[0], hw[1],
                hw[2], hw[3], hw[4], hw[5], qlen);
    } else {
        fprintf(out, "        unspec ");
        for (int i = 0; i < 16; ++i) {
            fprintf(out, "%s%02X", i ? "-" : "", i < link->hwaddr_len ? link->hwaddr[i] : 0);
        }
        fprintf(out, "  txqueuelen %d  (UNSPEC)\n", qlen);
    }

    IfcCounters c = ifcReadCounters(link);
    fprintf(out, "        RX packets %llu  bytes %llu (", c.rx_packets, c.rx_bytes);
    ifcPrintBytes(out, c.rx_bytes);
    fprintf(out, ")\n");
    fprintf(out, "        RX errors %llu  dropped %llu  overruns %llu  frame %llu\n", c.rx_errs, c.rx_drop,
            c.rx_fifo, c.rx_frame);
    fprintf(out, "        TX packets %llu  bytes %llu (", c.tx_packets, c.tx_bytes);
    ifcPrintBytes(out, c.tx_bytes);
    fprintf(out, ")\n");
    fprintf(out, "        TX errors %llu  dropped %llu overruns %llu  carrier %llu  collisions %llu\n", c.tx_errs,
            c.tx_drop, c.tx_fifo, c.tx_carrier, c.tx_colls);
    fputc('\n', out);
}

static void ifcPrintShort(FILE *out, const PscalNetLink *link) {
    unsigned flags = ifcLinuxFlags(link->flags);
    IfcCounters c = ifcReadCounters(link);
    fprintf(out, "%-16s%5u %8llu %6llu %6llu %-6llu %8llu %6llu %6llu %6llu ", link->name, link->mtu, c.rx_packets,
            c.rx_errs, c.rx_drop, c.rx_fifo, c.tx_packets, c.tx_errs, c.tx_drop, c.tx_fifo);
    /* net-tools' letters, in its order; P is both PROMISC and POINTOPOINT. */
    static const struct {
        unsigned value;
        char letter;
    } kLetters[] = {
        {0x200, 'A'}, {0x2, 'B'}, {0x4, 'D'}, {0x8, 'L'}, {0x1000, 'M'}, {0x8000, 'd'}, {0x100, 'P'},
        {0x20, 'N'}, {0x80, 'O'}, {0x10, 'P'}, {0x800, 's'}, {0x400, 'm'}, {0x40, 'R'}, {0x1, 'U'},
    };
    if (flags == 0) {
        fprintf(out, "[NO FLAGS]");
    }
    for (size_t i = 0; i < sizeof(kLetters) / sizeof(kLetters[0]); ++i) {
        if (flags & kLetters[i].value) {
            fputc(kLetters[i].letter, out);
        }
    }
    fputc('\n', out);
}

/* net-tools keeps its interface list in nstrcmp order: digits compare as
 * numbers, so utun10 follows utun9. */
static int ifcNameCompare(const char *a, const char *b) {
    while (*a && *b) {
        if (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
            unsigned long x = strtoul(a, (char **)&a, 10);
            unsigned long y = strtoul(b, (char **)&b, 10);
            if (x != y) {
                return x < y ? -1 : 1;
            }
            continue;
        }
        if (*a != *b) {
            return (unsigned char)*a - (unsigned char)*b;
        }
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int ifcLinkCompare(const void *x, const void *y) {
    const PscalNetLink *const *a = x, *const *b = y;
    return ifcNameCompare((*a)->name, (*b)->name);
}

static void ifcUsage(FILE *out) {
    fprintf(out, "Usage:\n"
                 "  ifconfig [-a] [-s] [interface]\n"
                 "  ifconfig interface [up|down|address|netmask N|broadcast B|mtu N ...]\n"
                 "\n"
                 "  -a  show all interfaces, including those that are down\n"
                 "  -s  show a short list, like netstat -i\n"
                 "\n"
                 "Changes are refused: this system's network is not configured from here.\n");
}

/* Which ioctl net-tools would have made for the first change requested. */
static const char *ifcRequestFor(const char *word) {
    if (strcmp(word, "netmask") == 0) {
        return "SIOCSIFNETMASK";
    }
    if (strcmp(word, "broadcast") == 0 || strcmp(word, "-broadcast") == 0) {
        return "SIOCSIFBRDADDR";
    }
    if (strcmp(word, "mtu") == 0) {
        return "SIOCSIFMTU";
    }
    if (strcmp(word, "pointopoint") == 0 || strcmp(word, "dstaddr") == 0) {
        return "SIOCSIFDSTADDR";
    }
    if (strcmp(word, "hw") == 0) {
        return "SIOCSIFHWADDR";
    }
    if (strcmp(word, "txqueuelen") == 0) {
        return "SIOCSIFTXQLEN";
    }
    if (strcmp(word, "add") == 0 || strcmp(word, "del") == 0 || strchr(word, ':')) {
        return "SIOCSIFADDR";
    }
    if (isdigit((unsigned char)word[0])) {
        return "SIOCSIFADDR";
    }
    return "SIOCSIFFLAGS";
}

int smallclueIfconfigCommand(int argc, char **argv) {
    bool all = false, brief = false;
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; ++i) {
        const char *opt = argv[i];
        if (strcmp(opt, "-a") == 0) {
            all = true;
        } else if (strcmp(opt, "-s") == 0) {
            brief = true;
        } else if (strcmp(opt, "-v") == 0) {
            /* net-tools' verbose only adds error detail. */
        } else if (strcmp(opt, "-h") == 0 || strcmp(opt, "--help") == 0) {
            ifcUsage(stdout);
            return 0;
        } else if (strcmp(opt, "-V") == 0 || strcmp(opt, "--version") == 0) {
            printf("ifconfig (SmallCLUE)\n");
            return 0;
        } else if (strcmp(opt, "-as") == 0 || strcmp(opt, "-sa") == 0) {
            all = brief = true;
        } else {
            ifcUsage(stderr);
            return 1;
        }
    }

    PscalNetSnapshot snap;
    if (!pscalNetSnapshotTake(&snap)) {
        fprintf(stderr, "ifconfig: no interfaces found\n");
        pscalNetSnapshotFree(&snap);
        return 1;
    }
    int rc = 0;
    const char *name = i < argc ? argv[i++] : NULL;
    if (name) {
        const PscalNetLink *link = pscalNetSnapshotFindLink(&snap, name);
        if (i < argc) {
            if (!link) {
                fprintf(stderr, "%s: ERROR while getting interface flags: No such device\n", name);
            } else {
                fprintf(stderr, "%s: Operation not permitted\n", ifcRequestFor(argv[i]));
            }
            rc = 255;
        } else if (!link) {
            fprintf(stderr, "%s: error fetching interface information: Device not found\n", name);
            rc = 1;
        } else if (brief) {
            printf("Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n");
            ifcPrintShort(stdout, link);
        } else {
            ifcPrintLong(stdout, link);
        }
    } else {
        const PscalNetLink **order = calloc(snap.link_count ? snap.link_count : 1, sizeof(*order));
        if (!order) {
            pscalNetSnapshotFree(&snap);
            fprintf(stderr, "ifconfig: out of memory\n");
            return 1;
        }
        for (size_t k = 0; k < snap.link_count; ++k) {
            order[k] = &snap.links[k];
        }
        qsort(order, snap.link_count, sizeof(*order), ifcLinkCompare);
        if (brief) {
            printf("Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n");
        }
        for (size_t k = 0; k < snap.link_count; ++k) {
            if (!all && !(order[k]->flags & IFF_UP)) {
                continue;
            }
            if (brief) {
                ifcPrintShort(stdout, order[k]);
            } else {
                ifcPrintLong(stdout, order[k]);
            }
        }
        free(order);
    }
    fflush(stdout);
    pscalNetSnapshotFree(&snap);
    return rc;
}
