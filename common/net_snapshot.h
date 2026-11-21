#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The machine's interfaces, addresses and routes, read once and named the way
 * Linux names them. The app's `ip` and its /proc/net files are both written from
 * one of these, so they can't disagree.
 *
 * Interfaces come from getifaddrs. Routes come from the kernel's routing table
 * (sysctl NET_RT_DUMP) where it can be read, and Linux's "proto kernel" prefix
 * routes are made from the addresses, as Linux's kernel makes them. Linux names:
 * the loopback interface is "lo" (Darwin's lo0), and link-local IPv6 addresses
 * lose the scope Darwin keeps in their third and fourth bytes. */

#define PSCAL_NET_NAME_MAX 32

typedef struct {
    int family;                 /* AF_INET or AF_INET6 */
    unsigned char addr[16];
    int prefixlen;
    bool has_broadcast;         /* IPv4 only */
    unsigned char broadcast[4];
    bool has_peer;              /* point-to-point */
    unsigned char peer[16];
} PscalNetAddress;

typedef struct {
    unsigned index;
    char name[PSCAL_NET_NAME_MAX];      /* Linux's: "lo" for lo0 */
    char host_name[PSCAL_NET_NAME_MAX]; /* the kernel's */
    unsigned flags;                     /* IFF_* */
    unsigned mtu;
    unsigned type;                      /* IFT_* on Darwin, 0 if unknown */
    unsigned char hwaddr[8];
    int hwaddr_len;
    uint64_t rx_bytes, rx_packets, rx_errors, rx_dropped, rx_multicast;
    uint64_t tx_bytes, tx_packets, tx_errors, tx_collisions;
    PscalNetAddress *addrs;
    size_t addr_count;
} PscalNetLink;

typedef struct {
    int family;
    unsigned char dst[16];
    int dst_len;                /* 0 for default */
    bool has_gateway;
    unsigned char gateway[16];
    unsigned ifindex;
    bool kernel;                /* made from an address: proto kernel scope link */
    bool has_src;
    unsigned char src[16];
} PscalNetRoute;

typedef struct {
    PscalNetLink *links;        /* by index */
    size_t link_count;
    PscalNetRoute *routes;      /* defaults first, then by destination */
    size_t route_count;
    bool routes_from_kernel;    /* the routing table was read */
} PscalNetSnapshot;

/* Reads the live state. False only when there was nothing at all to read. */
bool pscalNetSnapshotTake(PscalNetSnapshot *out);

/* The same from a given interface list (struct ifaddrs *) and routing-table dumps
 * in the shape sysctl NET_RT_DUMP returns, any of them NULL. For tests. */
bool pscalNetSnapshotBuild(PscalNetSnapshot *out, const void *ifaddrs_list,
                           const void *rt4, size_t rt4_len, const void *rt6, size_t rt6_len);

void pscalNetSnapshotFree(PscalNetSnapshot *snap);

/* By Linux's name, or the kernel's (lo0 finds lo). */
const PscalNetLink *pscalNetSnapshotFindLink(const PscalNetSnapshot *snap, const char *name);
const PscalNetLink *pscalNetSnapshotLinkByIndex(const PscalNetSnapshot *snap, unsigned index);

/* "UP", "DOWN" or "UNKNOWN", as operstate. */
const char *pscalNetLinkOperState(const PscalNetLink *link);
/* Linux's "loopback", "ether", "ppp" or "none". */
const char *pscalNetLinkType(const PscalNetLink *link);
/* The flag words between <>, comma-separated, in iproute2's order. */
void pscalNetLinkFlagWords(const PscalNetLink *link, char *buf, size_t len);
/* "host", "link", "site" or "global". */
const char *pscalNetAddressScope(int family, const unsigned char *addr);

/* The /proc/net files, in the Linux kernel's formats. */
void pscalNetWriteProcDev(const PscalNetSnapshot *snap, FILE *f);
void pscalNetWriteProcRoute(const PscalNetSnapshot *snap, FILE *f);
void pscalNetWriteProcIfInet6(const PscalNetSnapshot *snap, FILE *f);
void pscalNetWriteProcIpv6Route(const PscalNetSnapshot *snap, FILE *f);

#ifdef __cplusplus
}
#endif
