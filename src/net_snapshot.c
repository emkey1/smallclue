/* SmallCLUE's copy of pscal-core's src/common/net_snapshot.c, for every build
 * that does not link pscal-core: the stand-alone Linux and macOS SmallCLUE, and
 * AOK-Workstation's native programs. The PSCAL iOS app links pscal-core's own, so this
 * file is empty there.
 *
 * Added here: Linux. getifaddrs gives each interface's index, hardware address
 * and counters in an AF_PACKET entry, SIOCGIFMTU its MTU, and the routing tables
 * come from /proc/net/route and /proc/net/ipv6_route. /proc is also the answer
 * wherever the Darwin route dump is refused, which is how AOK's native programs
 * see the guest's routes. */
#if !defined(PSCAL_TARGET_IOS)

#include "common/net_snapshot.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__APPLE__)
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <sys/sysctl.h>
#endif

#if defined(__linux__)
#include <linux/if_link.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#include <stdlib.h>

#if defined(__APPLE__)
/* The iOS SDK has no net/route.h. These are Darwin's routing-socket messages as
 * net/route.h defines them, an ABI the kernel keeps for its own tools. */
typedef struct {
    uint32_t rmx_locks, rmx_mtu, rmx_hopcount;
    int32_t rmx_expire;
    uint32_t rmx_recvpipe, rmx_sendpipe, rmx_ssthresh, rmx_rtt, rmx_rttvar, rmx_pksent;
    uint32_t rmx_filler[4];
} PscalRtMetrics;

typedef struct {
    unsigned short rtm_msglen;
    unsigned char rtm_version;
    unsigned char rtm_type;
    unsigned short rtm_index;
    int rtm_flags;
    int rtm_addrs;
    pid_t rtm_pid;
    int rtm_seq;
    int rtm_errno;
    int rtm_use;
    uint32_t rtm_inits;
    PscalRtMetrics rtm_rmx;
} PscalRtMsghdr;

#define PSCAL_RTM_VERSION 5
#define PSCAL_NET_RT_DUMP 1
#define PSCAL_RTF_UP 0x1
#define PSCAL_RTF_GATEWAY 0x2
#define PSCAL_RTF_HOST 0x4
#define PSCAL_RTF_REJECT 0x8
#define PSCAL_RTF_LLINFO 0x400
#define PSCAL_RTF_BLACKHOLE 0x1000
#define PSCAL_RTF_WASCLONED 0x20000
#define PSCAL_RTF_LOCAL 0x200000
#define PSCAL_RTF_BROADCAST 0x400000
#define PSCAL_RTF_MULTICAST 0x800000
#define PSCAL_RTF_IFSCOPE 0x1000000
#define PSCAL_RTA_DST 0x1
#define PSCAL_RTA_GATEWAY 0x2
#define PSCAL_RTA_NETMASK 0x4
#define PSCAL_RTAX_MAX 8
#endif

/* Darwin shortens a route's mask to its last nonzero byte and may leave its family
 * unset, so the family comes from the address it masks. */
static int netPrefixFromMask(const struct sockaddr *mask, int family) {
    if (!mask) {
        return -1;
    }
    const unsigned char *bytes = NULL;
    size_t len = 0;
    if (family == AF_INET6) {
        bytes = ((const struct sockaddr_in6 *)mask)->sin6_addr.s6_addr;
        len = 16;
    } else {
        bytes = (const unsigned char *)&((const struct sockaddr_in *)mask)->sin_addr;
        len = 4;
    }
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = bytes[i];
        while (b & 0x80) {
            bits++;
            b = (unsigned char)(b << 1);
        }
        if (b != 0 || bytes[i] != 0xff) {
            break;
        }
    }
    return bits;
}

/* Darwin keeps a link-local or interface-local address's scope in bytes 2 and 3. */
static void netClearEmbeddedScope(unsigned char *addr16) {
    bool link_local = addr16[0] == 0xfe && (addr16[1] & 0xc0) == 0x80;
    bool scoped_multicast = addr16[0] == 0xff && ((addr16[1] & 0x0f) == 0x01 || (addr16[1] & 0x0f) == 0x02);
    if (link_local || scoped_multicast) {
        addr16[2] = 0;
        addr16[3] = 0;
    }
}

/* pscal-core renames lo0 to lo, because the PSCAL app has no Linux kernel to
 * name it. Every build of this copy has a kernel that names its own interfaces
 * -- Linux, macOS, or AOK-Workstation's, which keeps the host's lo0 -- and /proc/net
 * and the distribution's own ip and ifconfig use that name, so this does too. */
static void netLinuxName(const char *host, char *out, size_t len) {
    snprintf(out, len, "%s", host);
}

static PscalNetLink *netFindOrAddLink(PscalNetSnapshot *snap, size_t *cap, const char *host_name) {
    for (size_t i = 0; i < snap->link_count; ++i) {
        if (strcmp(snap->links[i].host_name, host_name) == 0) {
            return &snap->links[i];
        }
    }
    if (snap->link_count == *cap) {
        size_t next = *cap ? *cap * 2 : 16;
        PscalNetLink *grown = realloc(snap->links, next * sizeof(*grown));
        if (!grown) {
            return NULL;
        }
        snap->links = grown;
        *cap = next;
    }
    PscalNetLink *link = &snap->links[snap->link_count++];
    memset(link, 0, sizeof(*link));
    snprintf(link->host_name, sizeof(link->host_name), "%s", host_name);
    netLinuxName(host_name, link->name, sizeof(link->name));
    return link;
}

static bool netAddAddress(PscalNetLink *link, const PscalNetAddress *addr) {
    PscalNetAddress *grown = realloc(link->addrs, (link->addr_count + 1) * sizeof(*grown));
    if (!grown) {
        return false;
    }
    link->addrs = grown;
    link->addrs[link->addr_count++] = *addr;
    return true;
}

static bool netAddRoute(PscalNetSnapshot *snap, size_t *cap, const PscalNetRoute *route) {
    for (size_t i = 0; i < snap->route_count; ++i) {
        const PscalNetRoute *r = &snap->routes[i];
        if (r->family == route->family && r->dst_len == route->dst_len && r->ifindex == route->ifindex &&
            r->has_gateway == route->has_gateway && memcmp(r->dst, route->dst, 16) == 0 &&
            (!r->has_gateway || memcmp(r->gateway, route->gateway, 16) == 0)) {
            return true;
        }
    }
    if (snap->route_count == *cap) {
        size_t next = *cap ? *cap * 2 : 16;
        PscalNetRoute *grown = realloc(snap->routes, next * sizeof(*grown));
        if (!grown) {
            return false;
        }
        snap->routes = grown;
        *cap = next;
    }
    snap->routes[snap->route_count++] = *route;
    return true;
}

static void netMaskPrefix(unsigned char *addr, int family, int prefixlen) {
    int bytes = family == AF_INET ? 4 : 16;
    for (int i = 0; i < bytes; ++i) {
        int keep = prefixlen - i * 8;
        if (keep >= 8) {
            continue;
        }
        addr[i] = keep <= 0 ? 0 : (unsigned char)(addr[i] & (0xff << (8 - keep)));
    }
}

/* Linux's kernel adds a route for each address's prefix, and one to a
 * point-to-point peer. Loopback's live in the local table, which `ip route`
 * doesn't show. */
static void netAddKernelRoutes(PscalNetSnapshot *snap, size_t *cap) {
    for (size_t i = 0; i < snap->link_count; ++i) {
        const PscalNetLink *link = &snap->links[i];
        if (link->flags & IFF_LOOPBACK) {
            continue;
        }
        for (size_t j = 0; j < link->addr_count; ++j) {
            const PscalNetAddress *a = &link->addrs[j];
            PscalNetRoute r;
            memset(&r, 0, sizeof(r));
            r.family = a->family;
            r.ifindex = link->index;
            r.kernel = true;
            if (a->family == AF_INET) {
                r.has_src = true;
                memcpy(r.src, a->addr, 4);
            }
            if (a->has_peer) {
                memcpy(r.dst, a->peer, 16);
                r.dst_len = a->family == AF_INET ? 32 : 128;
            } else {
                int full = a->family == AF_INET ? 32 : 128;
                if (a->prefixlen <= 0 || a->prefixlen >= full) {
                    continue;
                }
                memcpy(r.dst, a->addr, 16);
                r.dst_len = a->prefixlen;
                netMaskPrefix(r.dst, a->family, a->prefixlen);
            }
            netAddRoute(snap, cap, &r);
        }
    }
}

#if defined(__APPLE__)
static size_t netSockaddrSpan(const struct sockaddr *sa) {
    size_t len = sa->sa_len ? sa->sa_len : sizeof(uint32_t);
    return (len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
}

/* Routes the kernel has that Linux's main table would: defaults and other routes
 * through a gateway, and on-link networks. Host, cloned, link-layer, local,
 * broadcast, multicast and interface-scoped copies are left out. */
static void netAddKernelTable(PscalNetSnapshot *snap, size_t *cap, int family, const unsigned char *buf, size_t len) {
    const unsigned char *cursor = buf;
    const unsigned char *end = buf + len;
    while (cursor + sizeof(PscalRtMsghdr) <= end) {
        const PscalRtMsghdr *rtm = (const PscalRtMsghdr *)cursor;
        if (rtm->rtm_msglen == 0 || cursor + rtm->rtm_msglen > end) {
            break;
        }
        const unsigned char *next = cursor + rtm->rtm_msglen;
        int skip = PSCAL_RTF_HOST | PSCAL_RTF_LLINFO | PSCAL_RTF_WASCLONED | PSCAL_RTF_LOCAL |
                   PSCAL_RTF_BROADCAST | PSCAL_RTF_MULTICAST | PSCAL_RTF_IFSCOPE | PSCAL_RTF_REJECT |
                   PSCAL_RTF_BLACKHOLE;
        if (rtm->rtm_version != PSCAL_RTM_VERSION || !(rtm->rtm_flags & PSCAL_RTF_UP) || (rtm->rtm_flags & skip)) {
            cursor = next;
            continue;
        }
        struct sockaddr_storage addrs[PSCAL_RTAX_MAX];
        memset(addrs, 0, sizeof(addrs));
        const unsigned char *sp = cursor + sizeof(PscalRtMsghdr);
        for (int i = 0; i < PSCAL_RTAX_MAX && sp < next; ++i) {
            if (!(rtm->rtm_addrs & (1 << i))) {
                continue;
            }
            const struct sockaddr *sa = (const struct sockaddr *)sp;
            size_t span = netSockaddrSpan(sa);
            size_t copy = sa->sa_len < sizeof(addrs[i]) ? sa->sa_len : sizeof(addrs[i]);
            if (sp + copy > next) {
                break;
            }
            memcpy(&addrs[i], sa, copy);
            sp += span;
        }
        const struct sockaddr *dst = (const struct sockaddr *)&addrs[0];
        const struct sockaddr *gw = (const struct sockaddr *)&addrs[1];
        const struct sockaddr *mask = (const struct sockaddr *)&addrs[2];
        if (!(rtm->rtm_addrs & PSCAL_RTA_DST) || dst->sa_family != family) {
            cursor = next;
            continue;
        }
        const PscalNetLink *link = pscalNetSnapshotLinkByIndex(snap, rtm->rtm_index);
        if (!link || (link->flags & IFF_LOOPBACK)) {
            cursor = next;
            continue;
        }
        PscalNetRoute r;
        memset(&r, 0, sizeof(r));
        r.family = family;
        r.ifindex = rtm->rtm_index;
        if (family == AF_INET) {
            memcpy(r.dst, &((const struct sockaddr_in *)dst)->sin_addr, 4);
        } else {
            memcpy(r.dst, &((const struct sockaddr_in6 *)dst)->sin6_addr, 16);
            netClearEmbeddedScope(r.dst);
        }
        int full = family == AF_INET ? 32 : 128;
        r.dst_len = (rtm->rtm_addrs & PSCAL_RTA_NETMASK) ? netPrefixFromMask(mask, family) : full;
        if (r.dst_len < 0) {
            r.dst_len = full;
        }
        netMaskPrefix(r.dst, family, r.dst_len);
        if (family == AF_INET && (r.dst[0] & 0xf0) == 0xe0) {
            cursor = next;
            continue;
        }
        if (family == AF_INET6 && r.dst[0] == 0xff) {
            cursor = next;
            continue;
        }
        if ((rtm->rtm_flags & PSCAL_RTF_GATEWAY) && (rtm->rtm_addrs & PSCAL_RTA_GATEWAY) && gw->sa_family == family) {
            r.has_gateway = true;
            if (family == AF_INET) {
                memcpy(r.gateway, &((const struct sockaddr_in *)gw)->sin_addr, 4);
            } else {
                memcpy(r.gateway, &((const struct sockaddr_in6 *)gw)->sin6_addr, 16);
                netClearEmbeddedScope(r.gateway);
            }
        } else if (rtm->rtm_flags & PSCAL_RTF_GATEWAY) {
            /* A gateway that is a link (a cellular default): on-link, as Linux says it. */
            r.has_gateway = false;
        }
        if (!r.has_gateway && r.dst_len == full) {
            /* A host on the link (the gateway, an own address, broadcast): Darwin's
             * cloned entries, which Linux keeps out of the main table. */
            cursor = next;
            continue;
        }
        if (!r.has_gateway && r.dst_len > 0) {
            /* An on-link network: the kernel route from the address says it already. */
            bool known = false;
            for (size_t i = 0; i < snap->route_count; ++i) {
                const PscalNetRoute *k = &snap->routes[i];
                if (k->kernel && k->family == family && k->ifindex == r.ifindex && k->dst_len == r.dst_len &&
                    memcmp(k->dst, r.dst, 16) == 0) {
                    known = true;
                    break;
                }
            }
            if (known) {
                cursor = next;
                continue;
            }
        }
        netAddRoute(snap, cap, &r);
        cursor = next;
    }
}

static unsigned char *netDumpRoutes(int family, size_t *len_out) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, PSCAL_NET_RT_DUMP, 0};
    for (int attempt = 0; attempt < 4; ++attempt) {
        size_t len = 0;
        if (sysctl(mib, 6, NULL, &len, NULL, 0) != 0 || len == 0) {
            return NULL;
        }
        len += len / 4 + 512;
        unsigned char *buf = malloc(len);
        if (!buf) {
            return NULL;
        }
        if (sysctl(mib, 6, buf, &len, NULL, 0) == 0) {
            *len_out = len;
            return buf;
        }
        free(buf);
    }
    return NULL;
}
#endif

#if defined(__linux__)
static unsigned netLinuxMtu(const char *name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    /* Interface names are IFNAMSIZ - 1 at most; a longer one is not a device. */
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%.*s", (int)sizeof(req.ifr_name) - 1, name);
    unsigned mtu = ioctl(fd, SIOCGIFMTU, &req) == 0 && req.ifr_mtu > 0 ? (unsigned)req.ifr_mtu : 0;
    close(fd);
    return mtu;
}
#endif

static int netHexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* 32 hex digits, most significant byte first, as /proc/net/ipv6_route writes them. */
static bool netParseHex16(const char *hex, unsigned char *out) {
    for (int i = 0; i < 16; ++i) {
        int hi = netHexNibble(hex[2 * i]), lo = netHexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return true;
}

/* The main routing table as Linux's /proc/net lists it: `ip route`'s table.
 * /proc/net/ipv6_route mixes in the local table, so its local and multicast
 * routes are left out, as `ip -6 route` leaves them out. Routes the kernel makes
 * for an address are already in the snapshot and netAddRoute keeps one of each. */
static bool netAddProcRoutes(PscalNetSnapshot *snap, size_t *cap) {
    bool read_any = false;
    char line[512];
    FILE *f = fopen("/proc/net/route", "r");
    if (f) {
        read_any = true;
        bool header = true;
        while (fgets(line, sizeof(line), f)) {
            if (header) {
                header = false;
                continue;
            }
            char iface[64];
            unsigned long dst, gw, mask;
            unsigned flags;
            if (sscanf(line, "%63s %lx %lx %x %*d %*u %*d %lx", iface, &dst, &gw, &flags, &mask) != 5) {
                continue;
            }
            if (!(flags & 0x0001) || (flags & 0x0200)) { /* RTF_UP; RTF_REJECT */
                continue;
            }
            const PscalNetLink *link = pscalNetSnapshotFindLink(snap, iface);
            if (!link) {
                continue;
            }
            PscalNetRoute r;
            memset(&r, 0, sizeof(r));
            r.family = AF_INET;
            r.ifindex = link->index;
            /* Each word is printed as the number it is in memory, so copying the
             * number back gives the address in network order. */
            uint32_t d32 = (uint32_t)dst, g32 = (uint32_t)gw, m32 = (uint32_t)mask;
            memcpy(r.dst, &d32, 4);
            const unsigned char *m = (const unsigned char *)&m32;
            for (int i = 0; i < 4; ++i) {
                for (int b = 7; b >= 0 && (m[i] >> b & 1); --b) {
                    r.dst_len++;
                }
            }
            if ((flags & 0x0002) && g32 != 0) { /* RTF_GATEWAY */
                r.has_gateway = true;
                memcpy(r.gateway, &g32, 4);
            }
            netAddRoute(snap, cap, &r);
        }
        fclose(f);
    }
    f = fopen("/proc/net/ipv6_route", "r");
    if (f) {
        read_any = true;
        while (fgets(line, sizeof(line), f)) {
            char dst_hex[33], gw_hex[33], iface[64];
            unsigned dst_len, flags;
            if (sscanf(line, "%32s %x %*32s %*x %32s %*x %*x %*x %x %63s", dst_hex, &dst_len, gw_hex, &flags,
                       iface) != 5) {
                continue;
            }
            if (!(flags & 0x0001) || (flags & 0x0200) || (flags & 0x80000000u)) { /* UP; REJECT; LOCAL */
                continue;
            }
            PscalNetRoute r;
            memset(&r, 0, sizeof(r));
            r.family = AF_INET6;
            if (!netParseHex16(dst_hex, r.dst) || !netParseHex16(gw_hex, r.gateway) || dst_len > 128) {
                continue;
            }
            if (r.dst[0] == 0xff) { /* multicast: the local table */
                continue;
            }
            const PscalNetLink *link = pscalNetSnapshotFindLink(snap, iface);
            if (!link) {
                continue;
            }
            r.dst_len = (int)dst_len;
            r.ifindex = link->index;
            static const unsigned char kZero[16];
            r.has_gateway = memcmp(r.gateway, kZero, 16) != 0;
            netAddRoute(snap, cap, &r);
        }
        fclose(f);
    }
    return read_any;
}

static int netCompareLinks(const void *a, const void *b) {
    const PscalNetLink *x = a, *y = b;
    return (x->index > y->index) - (x->index < y->index);
}

static int netAddressRank(const PscalNetAddress *a) {
    if (a->family == AF_INET) {
        return 0;
    }
    return strcmp(pscalNetAddressScope(a->family, a->addr), "link") == 0 ? 2 : 1;
}

static int netCompareAddresses(const void *a, const void *b) {
    int x = netAddressRank(a), y = netAddressRank(b);
    return (x > y) - (x < y);
}

static int netCompareRoutes(const void *a, const void *b) {
    const PscalNetRoute *x = a, *y = b;
    if (x->family != y->family) {
        return x->family == AF_INET ? -1 : 1;
    }
    if ((x->dst_len == 0) != (y->dst_len == 0)) {
        return x->dst_len == 0 ? -1 : 1;
    }
    int c = memcmp(x->dst, y->dst, x->family == AF_INET ? 4 : 16);
    if (c != 0) {
        return c;
    }
    if (x->dst_len != y->dst_len) {
        return x->dst_len - y->dst_len;
    }
    return (x->ifindex > y->ifindex) - (x->ifindex < y->ifindex);
}

bool pscalNetSnapshotBuild(PscalNetSnapshot *out, const void *ifaddrs_list,
                           const void *rt4, size_t rt4_len, const void *rt6, size_t rt6_len) {
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    size_t link_cap = 0;
    for (const struct ifaddrs *ifa = ifaddrs_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_name[0]) {
            continue;
        }
        PscalNetLink *link = netFindOrAddLink(out, &link_cap, ifa->ifa_name);
        if (!link) {
            continue;
        }
        link->flags = ifa->ifa_flags;
#if defined(__APPLE__)
        /* Darwin sets IFF_NOTRAILERS on every interface; Linux never does, and
         * AOK-Workstation's kernel leaves it out of what a guest's ip and ifconfig see. */
        link->flags &= ~(unsigned)IFF_NOTRAILERS;
#endif
        const struct sockaddr *sa = ifa->ifa_addr;
        if (!sa) {
            continue;
        }
#if defined(__APPLE__)
        if (sa->sa_family == AF_LINK) {
            const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)sa;
            link->index = sdl->sdl_index;
            link->type = sdl->sdl_type;
            if (sdl->sdl_alen > 0 && sdl->sdl_alen <= sizeof(link->hwaddr)) {
                memcpy(link->hwaddr, LLADDR(sdl), sdl->sdl_alen);
                link->hwaddr_len = sdl->sdl_alen;
            }
            if (ifa->ifa_data) {
                const struct if_data *d = ifa->ifa_data;
                link->mtu = d->ifi_mtu;
                if (!link->type) {
                    link->type = d->ifi_type;
                }
                link->rx_bytes = d->ifi_ibytes;
                link->rx_packets = d->ifi_ipackets;
                link->rx_errors = d->ifi_ierrors;
                link->rx_dropped = d->ifi_iqdrops;
                link->rx_multicast = d->ifi_imcasts;
                link->tx_bytes = d->ifi_obytes;
                link->tx_packets = d->ifi_opackets;
                link->tx_errors = d->ifi_oerrors;
                link->tx_collisions = d->ifi_collisions;
            }
            continue;
        }
#endif
#if defined(__linux__)
        if (sa->sa_family == AF_PACKET) {
            const struct sockaddr_ll *sll = (const struct sockaddr_ll *)sa;
            link->index = (unsigned)sll->sll_ifindex;
            link->type = sll->sll_hatype;
            if (sll->sll_halen > 0 && sll->sll_halen <= sizeof(link->hwaddr)) {
                memcpy(link->hwaddr, sll->sll_addr, sll->sll_halen);
                link->hwaddr_len = sll->sll_halen;
            }
            if (ifa->ifa_data) {
                const struct rtnl_link_stats *d = ifa->ifa_data;
                link->rx_bytes = d->rx_bytes;
                link->rx_packets = d->rx_packets;
                link->rx_errors = d->rx_errors;
                link->rx_dropped = d->rx_dropped;
                link->rx_multicast = d->multicast;
                link->tx_bytes = d->tx_bytes;
                link->tx_packets = d->tx_packets;
                link->tx_errors = d->tx_errors;
                link->tx_collisions = d->collisions;
            }
            continue;
        }
#endif
        if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
            continue;
        }
        PscalNetAddress a;
        memset(&a, 0, sizeof(a));
        a.family = sa->sa_family;
        if (a.family == AF_INET) {
            memcpy(a.addr, &((const struct sockaddr_in *)sa)->sin_addr, 4);
        } else {
            memcpy(a.addr, &((const struct sockaddr_in6 *)sa)->sin6_addr, 16);
            netClearEmbeddedScope(a.addr);
        }
        int full = a.family == AF_INET ? 32 : 128;
        a.prefixlen = ifa->ifa_netmask ? netPrefixFromMask(ifa->ifa_netmask, a.family) : full;
        if (a.prefixlen < 0) {
            a.prefixlen = full;
        }
        const struct sockaddr *other = ifa->ifa_dstaddr;
        if (other && other->sa_family == a.family) {
            if (ifa->ifa_flags & IFF_POINTOPOINT) {
                a.has_peer = true;
                if (a.family == AF_INET) {
                    memcpy(a.peer, &((const struct sockaddr_in *)other)->sin_addr, 4);
                } else {
                    memcpy(a.peer, &((const struct sockaddr_in6 *)other)->sin6_addr, 16);
                    netClearEmbeddedScope(a.peer);
                }
                /* iproute2 names a peer only when it isn't the local address. */
                a.has_peer = memcmp(a.peer, a.addr, a.family == AF_INET ? 4 : 16) != 0;
            } else if ((ifa->ifa_flags & IFF_BROADCAST) && a.family == AF_INET) {
                a.has_broadcast = true;
                memcpy(a.broadcast, &((const struct sockaddr_in *)other)->sin_addr, 4);
            }
        }
        netAddAddress(link, &a);
    }
    for (size_t i = 0; i < out->link_count; ++i) {
        PscalNetLink *link = &out->links[i];
        if (link->index == 0) {
            link->index = if_nametoindex(link->host_name);
        }
#if defined(__linux__)
        if (link->mtu == 0) {
            link->mtu = netLinuxMtu(link->host_name);
        }
#endif
        if (link->mtu == 0 && (link->flags & IFF_LOOPBACK)) {
            link->mtu = 65536;
        }
        if (link->addr_count > 1) {
            /* Stable: the kernel's order within a rank. */
            for (size_t a = 1; a < link->addr_count; ++a) {
                PscalNetAddress key = link->addrs[a];
                size_t b = a;
                while (b > 0 && netCompareAddresses(&link->addrs[b - 1], &key) > 0) {
                    link->addrs[b] = link->addrs[b - 1];
                    b--;
                }
                link->addrs[b] = key;
            }
        }
    }
    if (out->link_count > 1) {
        qsort(out->links, out->link_count, sizeof(out->links[0]), netCompareLinks);
    }

    size_t route_cap = 0;
    netAddKernelRoutes(out, &route_cap);
#if defined(__APPLE__)
    if (rt4 && rt4_len) {
        netAddKernelTable(out, &route_cap, AF_INET, rt4, rt4_len);
        out->routes_from_kernel = true;
    }
    if (rt6 && rt6_len) {
        netAddKernelTable(out, &route_cap, AF_INET6, rt6, rt6_len);
        out->routes_from_kernel = true;
    }
#else
    (void)rt4;
    (void)rt4_len;
    (void)rt6;
    (void)rt6_len;
#endif
    if (out->route_count > 1) {
        qsort(out->routes, out->route_count, sizeof(out->routes[0]), netCompareRoutes);
    }
    return true;
}

bool pscalNetSnapshotTake(PscalNetSnapshot *out) {
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) {
        list = NULL;
    }
    unsigned char *rt4 = NULL, *rt6 = NULL;
    size_t rt4_len = 0, rt6_len = 0;
#if defined(__APPLE__)
    rt4 = netDumpRoutes(AF_INET, &rt4_len);
    rt6 = netDumpRoutes(AF_INET6, &rt6_len);
#endif
    bool ok = pscalNetSnapshotBuild(out, list, rt4, rt4_len, rt6, rt6_len);
    free(rt4);
    free(rt6);
    if (ok && !out->routes_from_kernel) {
        size_t cap = out->route_count;
        if (netAddProcRoutes(out, &cap)) {
            out->routes_from_kernel = true;
            if (out->route_count > 1) {
                qsort(out->routes, out->route_count, sizeof(out->routes[0]), netCompareRoutes);
            }
        }
    }
    if (list) {
        freeifaddrs(list);
    }
    return ok && out->link_count > 0;
}

void pscalNetSnapshotFree(PscalNetSnapshot *snap) {
    if (!snap) {
        return;
    }
    for (size_t i = 0; i < snap->link_count; ++i) {
        free(snap->links[i].addrs);
    }
    free(snap->links);
    free(snap->routes);
    memset(snap, 0, sizeof(*snap));
}

const PscalNetLink *pscalNetSnapshotFindLink(const PscalNetSnapshot *snap, const char *name) {
    if (!snap || !name) {
        return NULL;
    }
    for (size_t i = 0; i < snap->link_count; ++i) {
        if (strcmp(snap->links[i].name, name) == 0 || strcmp(snap->links[i].host_name, name) == 0) {
            return &snap->links[i];
        }
    }
    return NULL;
}

const PscalNetLink *pscalNetSnapshotLinkByIndex(const PscalNetSnapshot *snap, unsigned index) {
    if (!snap || index == 0) {
        return NULL;
    }
    for (size_t i = 0; i < snap->link_count; ++i) {
        if (snap->links[i].index == index) {
            return &snap->links[i];
        }
    }
    return NULL;
}

const char *pscalNetLinkOperState(const PscalNetLink *link) {
    if (!link) {
        return "UNKNOWN";
    }
    if (link->flags & IFF_LOOPBACK) {
        return "UNKNOWN";
    }
    return ((link->flags & IFF_UP) && (link->flags & IFF_RUNNING)) ? "UP" : "DOWN";
}

const char *pscalNetLinkType(const PscalNetLink *link) {
    if (!link) {
        return "none";
    }
    if (link->flags & IFF_LOOPBACK) {
        return "loopback";
    }
#if defined(__APPLE__)
    if (link->type == IFT_PPP) {
        return "ppp";
    }
    if ((link->type == IFT_ETHER || link->type == IFT_BRIDGE || link->type == IFT_L2VLAN) && link->hwaddr_len == 6) {
        return "ether";
    }
#else
#if defined(__linux__)
    if (link->type == ARPHRD_PPP) {
        return "ppp";
    }
    if (link->type != 0 && link->type != ARPHRD_ETHER) {
        return "none";
    }
#endif
    if (link->hwaddr_len == 6) {
        return "ether";
    }
#endif
    return "none";
}

void pscalNetLinkFlagWords(const PscalNetLink *link, char *buf, size_t len) {
    if (!buf || len == 0) {
        return;
    }
    buf[0] = '\0';
    if (!link) {
        return;
    }
    static const struct {
        unsigned flag;
        const char *word;
    } kWords[] = {
        {IFF_LOOPBACK, "LOOPBACK"}, {IFF_BROADCAST, "BROADCAST"}, {IFF_POINTOPOINT, "POINTOPOINT"},
        {IFF_MULTICAST, "MULTICAST"}, {IFF_NOARP, "NOARP"}, {IFF_ALLMULTI, "ALLMULTI"},
        {IFF_PROMISC, "PROMISC"}, {IFF_DEBUG, "DEBUG"}, {IFF_NOTRAILERS, "NOTRAILERS"},
        {IFF_UP, "UP"}, {IFF_RUNNING, "LOWER_UP"},
    };
    size_t used = 0;
    /* iproute2 says NO-CARRIER, first, for a link that is up with no carrier. */
    if ((link->flags & IFF_UP) && !(link->flags & IFF_RUNNING)) {
        used += (size_t)snprintf(buf + used, len - used, "NO-CARRIER");
    }
    for (size_t i = 0; i < sizeof(kWords) / sizeof(kWords[0]) && used < len; ++i) {
        if (!(link->flags & kWords[i].flag)) {
            continue;
        }
        used += (size_t)snprintf(buf + used, len - used, "%s%s", used ? "," : "", kWords[i].word);
    }
}

const char *pscalNetAddressScope(int family, const unsigned char *addr) {
    if (family == AF_INET) {
        if (addr[0] == 127) {
            return "host";
        }
        if (addr[0] == 169 && addr[1] == 254) {
            return "link";
        }
        return "global";
    }
    static const unsigned char kLoopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(addr, kLoopback6, 16) == 0) {
        return "host";
    }
    if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) {
        return "link";
    }
    if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0xc0) {
        return "site";
    }
    return "global";
}

void pscalNetWriteProcDev(const PscalNetSnapshot *snap, FILE *f) {
    if (!f) {
        return;
    }
    fprintf(f, "Inter-|   Receive                                                |  Transmit\n"
               " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
    for (size_t i = 0; snap && i < snap->link_count; ++i) {
        const PscalNetLink *l = &snap->links[i];
        fprintf(f, "%6s: %7llu %7llu %4llu %4llu %4llu %5llu %10llu %9llu %8llu %7llu %4llu %4llu %4llu %5llu %7llu %10llu\n",
                l->name, (unsigned long long)l->rx_bytes, (unsigned long long)l->rx_packets,
                (unsigned long long)l->rx_errors, (unsigned long long)l->rx_dropped, 0ULL, 0ULL, 0ULL,
                (unsigned long long)l->rx_multicast, (unsigned long long)l->tx_bytes,
                (unsigned long long)l->tx_packets, (unsigned long long)l->tx_errors, 0ULL, 0ULL,
                (unsigned long long)l->tx_collisions, 0ULL, 0ULL);
    }
}

static uint32_t netRawIpv4(const unsigned char *bytes) {
    uint32_t v;
    memcpy(&v, bytes, 4);
    return v;
}

void pscalNetWriteProcRoute(const PscalNetSnapshot *snap, FILE *f) {
    if (!f) {
        return;
    }
    char line[160];
    fprintf(f, "%-127s\n", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT");
    for (size_t i = 0; snap && i < snap->route_count; ++i) {
        const PscalNetRoute *r = &snap->routes[i];
        if (r->family != AF_INET) {
            continue;
        }
        const PscalNetLink *link = pscalNetSnapshotLinkByIndex(snap, r->ifindex);
        unsigned char mask[4] = {0};
        for (int b = 0; b < r->dst_len && b < 32; ++b) {
            mask[b / 8] |= (unsigned char)(0x80 >> (b % 8));
        }
        unsigned flags = 0x0001 | (r->has_gateway ? 0x0002 : 0) | (r->dst_len == 32 ? 0x0004 : 0);
        /* The kernel prints each big-endian word as the number it is in memory. */
        snprintf(line, sizeof(line), "%s\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u",
                 link ? link->name : "*", netRawIpv4(r->dst), r->has_gateway ? netRawIpv4(r->gateway) : 0u,
                 flags, 0, 0u, 0, netRawIpv4(mask), 0, 0u, 0u);
        fprintf(f, "%-127s\n", line);
    }
}

void pscalNetWriteProcIfInet6(const PscalNetSnapshot *snap, FILE *f) {
    if (!f) {
        return;
    }
    for (size_t i = 0; snap && i < snap->link_count; ++i) {
        const PscalNetLink *l = &snap->links[i];
        for (size_t j = 0; j < l->addr_count; ++j) {
            const PscalNetAddress *a = &l->addrs[j];
            if (a->family != AF_INET6) {
                continue;
            }
            const char *scope = pscalNetAddressScope(AF_INET6, a->addr);
            unsigned scope_bits = strcmp(scope, "host") == 0 ? 0x10 : strcmp(scope, "link") == 0 ? 0x20
                                : strcmp(scope, "site") == 0 ? 0x40 : 0x00;
            for (int b = 0; b < 16; ++b) {
                fprintf(f, "%02x", a->addr[b]);
            }
            /* 0x80: IFA_F_PERMANENT. */
            fprintf(f, " %02x %02x %02x %02x %8s\n", l->index & 0xffu, (unsigned)a->prefixlen & 0xffu,
                    scope_bits, 0x80u, l->name);
        }
    }
}

void pscalNetWriteProcIpv6Route(const PscalNetSnapshot *snap, FILE *f) {
    if (!f) {
        return;
    }
    for (size_t i = 0; snap && i < snap->route_count; ++i) {
        const PscalNetRoute *r = &snap->routes[i];
        if (r->family != AF_INET6) {
            continue;
        }
        const PscalNetLink *link = pscalNetSnapshotLinkByIndex(snap, r->ifindex);
        for (int b = 0; b < 16; ++b) {
            fprintf(f, "%02x", r->dst[b]);
        }
        fprintf(f, " %02x 00000000000000000000000000000000 00 ", (unsigned)r->dst_len & 0xffu);
        for (int b = 0; b < 16; ++b) {
            fprintf(f, "%02x", r->has_gateway ? r->gateway[b] : 0);
        }
        /* Linux's metrics: 256 for a prefix route, 1024 for a default. */
        fprintf(f, " %08x %08x %08x %08x %8s\n", r->dst_len == 0 ? 1024u : 256u, 1u, 0u,
                0x0001u | (r->has_gateway ? 0x0002u : 0u), link ? link->name : "lo");
    }
}

#endif /* !PSCAL_TARGET_IOS */
