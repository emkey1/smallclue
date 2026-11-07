/* ip: show the device's interfaces, addresses and routes, the way iproute2's ip
 * does on Linux -- same objects, words, layout and exit statuses.
 *
 *   ip [-4|-6|-0] [-br] [-j [-p]] [-o] [-f FAMILY] address [show [dev] NAME] [up]
 *   ip ... link [show [dev] NAME] [up]
 *   ip ... route [show] [dev NAME] [default] | route get ADDRESS
 *
 * The data is pscal-core's net snapshot, which also writes /proc/net/dev, route,
 * if_inet6 and ipv6_route, so the two always agree. The app can't configure the
 * device's network, so every change is refused as Linux refuses an unprivileged
 * user, root included: "RTNETLINK answers: Operation not permitted", status 2.
 *
 * iOS only. On Linux the real ip is there, and macOS has its own tools. */

#if defined(PSCAL_TARGET_IOS)

#include "ip_app.h"

#include "common/net_snapshot.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IP_FAMILY_LINK (-1)

typedef struct {
    int family; /* AF_UNSPEC, AF_INET, AF_INET6 or IP_FAMILY_LINK */
    bool brief;
    bool json;
    bool pretty;
    bool oneline;
    const PscalNetSnapshot *snap;
    FILE *out;
    FILE *err;
} IpContext;

/* iproute2's matches(): a nonempty prefix of the word. */
static bool ipMatches(const char *arg, const char *word) {
    size_t len = strlen(arg);
    return len > 0 && len <= strlen(word) && strncmp(arg, word, len) == 0;
}

static int ipUsage(IpContext *ctx) {
    fprintf(ctx->err,
            "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
            "where  OBJECT := { address | link | route }\n"
            "       OPTIONS := { -4 | -6 | -0 | -br[ief] | -j[son] | -p[retty] |\n"
            "                    -o[neline] | -f[amily] { inet | inet6 | link } }\n");
    return 255;
}

static int ipRefuse(IpContext *ctx) {
    fprintf(ctx->err, "RTNETLINK answers: Operation not permitted\n");
    return 2;
}

static const char *ipFormatAddr(int family, const unsigned char *addr, char *buf, size_t len) {
    if (!inet_ntop(family, addr, buf, (socklen_t)len)) {
        snprintf(buf, len, "?");
    }
    return buf;
}

static void ipFormatHw(const PscalNetLink *link, char *buf, size_t len, bool broadcast) {
    buf[0] = '\0';
    bool loopback = (link->flags & IFF_LOOPBACK) != 0;
    int n = loopback ? 6 : link->hwaddr_len;
    size_t used = 0;
    for (int i = 0; i < n && used < len; ++i) {
        unsigned char b = loopback ? 0 : broadcast ? 0xff : link->hwaddr[i];
        used += (size_t)snprintf(buf + used, len - used, "%s%02x", i ? ":" : "", b);
    }
}

static bool ipLinkHasHw(const PscalNetLink *link) {
    const char *type = pscalNetLinkType(link);
    return strcmp(type, "loopback") == 0 || strcmp(type, "ether") == 0;
}

static bool ipWantFamily(const IpContext *ctx, int family) {
    return ctx->family == AF_UNSPEC || ctx->family == family;
}

static bool ipLinkHasFamily(const IpContext *ctx, const PscalNetLink *link) {
    if (ctx->family == AF_UNSPEC || ctx->family == IP_FAMILY_LINK) {
        return true;
    }
    for (size_t i = 0; i < link->addr_count; ++i) {
        if (link->addrs[i].family == ctx->family) {
            return true;
        }
    }
    return false;
}

/* ---- JSON ---- */

static void ipJsonString(FILE *out, const char *s) {
    fputc('"', out);
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fprintf(out, "\\%c", c);
        } else if (c < 0x20) {
            fprintf(out, "\\u%04x", c);
        } else {
            fputc(c, out);
        }
    }
    fputc('"', out);
}

static void ipJsonKey(FILE *out, bool *first, const char *key) {
    if (!*first) {
        fputc(',', out);
    }
    *first = false;
    ipJsonString(out, key);
    fputc(':', out);
}

static void ipJsonKeyString(FILE *out, bool *first, const char *key, const char *value) {
    ipJsonKey(out, first, key);
    ipJsonString(out, value);
}

static void ipJsonKeyNumber(FILE *out, bool *first, const char *key, unsigned long long value) {
    ipJsonKey(out, first, key);
    fprintf(out, "%llu", value);
}

static void ipJsonFlags(FILE *out, bool *first, const PscalNetLink *link) {
    char words[256];
    pscalNetLinkFlagWords(link, words, sizeof(words));
    ipJsonKey(out, first, "flags");
    fputc('[', out);
    bool any = false;
    for (char *save = NULL, *w = strtok_r(words, ",", &save); w; w = strtok_r(NULL, ",", &save)) {
        if (any) {
            fputc(',', out);
        }
        any = true;
        ipJsonString(out, w);
    }
    fputc(']', out);
}

/* The compact text, laid out four spaces to a level. */
static void ipJsonPretty(FILE *out, const char *text) {
    int depth = 0;
    bool in_string = false;
    for (const char *p = text; *p; ++p) {
        char c = *p;
        if (in_string) {
            fputc(c, out);
            if (c == '\\' && p[1]) {
                fputc(*++p, out);
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        switch (c) {
        case '"':
            in_string = true;
            fputc(c, out);
            break;
        case '[':
        case '{':
            fputc(c, out);
            if (p[1] == (c == '[' ? ']' : '}')) {
                fputc(*++p, out);
                break;
            }
            depth++;
            fprintf(out, "\n%*s", depth * 4, "");
            break;
        case ']':
        case '}':
            depth--;
            fprintf(out, "\n%*s%c", depth * 4, "", c);
            break;
        case ',':
            fprintf(out, ",\n%*s", depth * 4, "");
            break;
        case ':':
            fputs(": ", out);
            break;
        default:
            fputc(c, out);
        }
    }
}

/* ---- address and link ---- */

static void ipPrintLinkHeader(IpContext *ctx, const PscalNetLink *link, bool link_object) {
    char words[256];
    pscalNetLinkFlagWords(link, words, sizeof(words));
    fprintf(ctx->out, "%u: %s: <%s> mtu %u state %s %sgroup default", link->index, link->name, words, link->mtu,
            pscalNetLinkOperState(link), link_object ? "mode DEFAULT " : "");
}

static void ipPrintLinkLine(IpContext *ctx, const PscalNetLink *link) {
    fprintf(ctx->out, "    link/%s ", pscalNetLinkType(link));
    if (ipLinkHasHw(link)) {
        char hw[32], brd[32];
        ipFormatHw(link, hw, sizeof(hw), false);
        ipFormatHw(link, brd, sizeof(brd), true);
        fprintf(ctx->out, "%s brd %s", hw, brd);
    }
}

static void ipPrintAddress(IpContext *ctx, const PscalNetLink *link, const PscalNetAddress *a) {
    char addr[INET6_ADDRSTRLEN], other[INET6_ADDRSTRLEN];
    const char *sep = ctx->oneline ? "\\" : "\n";
    if (ctx->oneline) {
        fprintf(ctx->out, "%u: %s", link->index, link->name);
    }
    fprintf(ctx->out, "    %s %s", a->family == AF_INET ? "inet" : "inet6",
            ipFormatAddr(a->family, a->addr, addr, sizeof(addr)));
    if (a->has_peer) {
        fprintf(ctx->out, " peer %s", ipFormatAddr(a->family, a->peer, other, sizeof(other)));
    }
    fprintf(ctx->out, "/%d", a->prefixlen);
    if (a->has_broadcast) {
        fprintf(ctx->out, " brd %s", ipFormatAddr(AF_INET, a->broadcast, other, sizeof(other)));
    }
    fprintf(ctx->out, " scope %s", pscalNetAddressScope(a->family, a->addr));
    if (a->family == AF_INET) {
        fprintf(ctx->out, " %s", link->name);
    }
    fprintf(ctx->out, "%s       valid_lft forever preferred_lft forever\n", sep);
}

static void ipJsonLink(IpContext *ctx, const PscalNetLink *link, bool link_object, bool with_addrs) {
    FILE *out = ctx->out;
    bool first = true;
    fputc('{', out);
    ipJsonKeyNumber(out, &first, "ifindex", link->index);
    ipJsonKeyString(out, &first, "ifname", link->name);
    ipJsonFlags(out, &first, link);
    ipJsonKeyNumber(out, &first, "mtu", link->mtu);
    ipJsonKeyString(out, &first, "operstate", pscalNetLinkOperState(link));
    if (link_object) {
        ipJsonKeyString(out, &first, "linkmode", "DEFAULT");
    }
    ipJsonKeyString(out, &first, "group", "default");
    if (ctx->family == AF_UNSPEC || ctx->family == IP_FAMILY_LINK || link_object) {
        ipJsonKeyString(out, &first, "link_type", pscalNetLinkType(link));
        if (ipLinkHasHw(link)) {
            char hw[32];
            ipFormatHw(link, hw, sizeof(hw), false);
            ipJsonKeyString(out, &first, "address", hw);
            ipFormatHw(link, hw, sizeof(hw), true);
            ipJsonKeyString(out, &first, "broadcast", hw);
        }
    }
    if (with_addrs) {
        ipJsonKey(out, &first, "addr_info");
        fputc('[', out);
        bool any = false;
        for (size_t i = 0; ctx->family != IP_FAMILY_LINK && i < link->addr_count; ++i) {
            const PscalNetAddress *a = &link->addrs[i];
            if (!ipWantFamily(ctx, a->family)) {
                continue;
            }
            char buf[INET6_ADDRSTRLEN];
            bool f = true;
            if (any) {
                fputc(',', out);
            }
            any = true;
            fputc('{', out);
            ipJsonKeyString(out, &f, "family", a->family == AF_INET ? "inet" : "inet6");
            ipJsonKeyString(out, &f, "local", ipFormatAddr(a->family, a->addr, buf, sizeof(buf)));
            if (a->has_peer) {
                ipJsonKeyString(out, &f, "address", ipFormatAddr(a->family, a->peer, buf, sizeof(buf)));
            }
            ipJsonKeyNumber(out, &f, "prefixlen", (unsigned)a->prefixlen);
            if (a->has_broadcast) {
                ipJsonKeyString(out, &f, "broadcast", ipFormatAddr(AF_INET, a->broadcast, buf, sizeof(buf)));
            }
            ipJsonKeyString(out, &f, "scope", pscalNetAddressScope(a->family, a->addr));
            if (a->family == AF_INET) {
                ipJsonKeyString(out, &f, "label", link->name);
            }
            ipJsonKeyNumber(out, &f, "valid_life_time", 4294967295ULL);
            ipJsonKeyNumber(out, &f, "preferred_life_time", 4294967295ULL);
            fputc('}', out);
        }
        fputc(']', out);
    }
    fputc('}', out);
}

static void ipJsonBrief(IpContext *ctx, const PscalNetLink *link, bool link_object) {
    FILE *out = ctx->out;
    bool first = true;
    fputc('{', out);
    ipJsonKeyString(out, &first, "ifname", link->name);
    ipJsonKeyString(out, &first, "operstate", pscalNetLinkOperState(link));
    if (link_object) {
        if (ipLinkHasHw(link)) {
            char hw[32];
            ipFormatHw(link, hw, sizeof(hw), false);
            ipJsonKeyString(out, &first, "address", hw);
        }
        ipJsonFlags(out, &first, link);
    } else {
        ipJsonKey(out, &first, "addr_info");
        fputc('[', out);
        bool any = false;
        for (size_t i = 0; ctx->family != IP_FAMILY_LINK && i < link->addr_count; ++i) {
            const PscalNetAddress *a = &link->addrs[i];
            if (!ipWantFamily(ctx, a->family)) {
                continue;
            }
            char buf[INET6_ADDRSTRLEN];
            bool f = true;
            if (any) {
                fputc(',', out);
            }
            any = true;
            fputc('{', out);
            ipJsonKeyString(out, &f, "local", ipFormatAddr(a->family, a->addr, buf, sizeof(buf)));
            ipJsonKeyNumber(out, &f, "prefixlen", (unsigned)a->prefixlen);
            fputc('}', out);
        }
        fputc(']', out);
    }
    fputc('}', out);
}

static void ipPrintBrief(IpContext *ctx, const PscalNetLink *link, bool link_object) {
    fprintf(ctx->out, "%-16s %-14s ", link->name, pscalNetLinkOperState(link));
    if (link_object) {
        if (ipLinkHasHw(link)) {
            char hw[32];
            ipFormatHw(link, hw, sizeof(hw), false);
            fprintf(ctx->out, "%s ", hw);
        }
        char words[256];
        pscalNetLinkFlagWords(link, words, sizeof(words));
        fprintf(ctx->out, "<%s> ", words);
    } else {
        for (size_t i = 0; ctx->family != IP_FAMILY_LINK && i < link->addr_count; ++i) {
            const PscalNetAddress *a = &link->addrs[i];
            if (!ipWantFamily(ctx, a->family)) {
                continue;
            }
            char buf[INET6_ADDRSTRLEN], peer[INET6_ADDRSTRLEN];
            if (a->has_peer) {
                fprintf(ctx->out, "%s peer %s/%d ", ipFormatAddr(a->family, a->addr, buf, sizeof(buf)),
                        ipFormatAddr(a->family, a->peer, peer, sizeof(peer)), a->prefixlen);
            } else {
                fprintf(ctx->out, "%s/%d ", ipFormatAddr(a->family, a->addr, buf, sizeof(buf)), a->prefixlen);
            }
        }
    }
    fputc('\n', ctx->out);
}

static void ipShowOne(IpContext *ctx, const PscalNetLink *link, bool link_object, bool *first_json) {
    if (ctx->json) {
        if (!*first_json) {
            fputc(',', ctx->out);
        }
        *first_json = false;
        if (ctx->brief) {
            ipJsonBrief(ctx, link, link_object);
        } else {
            ipJsonLink(ctx, link, link_object, !link_object);
        }
        return;
    }
    if (ctx->brief) {
        ipPrintBrief(ctx, link, link_object);
        return;
    }
    bool show_link = link_object || ctx->family == AF_UNSPEC || ctx->family == IP_FAMILY_LINK;
    if (!ctx->oneline || link_object) {
        ipPrintLinkHeader(ctx, link, link_object);
        if (show_link) {
            fputs(ctx->oneline ? "\\" : "\n", ctx->out);
            ipPrintLinkLine(ctx, link);
        }
        fputc('\n', ctx->out);
    }
    if (link_object) {
        return;
    }
    for (size_t i = 0; ctx->family != IP_FAMILY_LINK && i < link->addr_count; ++i) {
        if (ipWantFamily(ctx, link->addrs[i].family)) {
            ipPrintAddress(ctx, link, &link->addrs[i]);
        }
    }
}

/* With JSON the whole answer is built first, so -p can lay it out. */
static FILE *ipJsonBegin(IpContext *ctx, char **buf, size_t *len, FILE **saved) {
    *saved = ctx->out;
    *buf = NULL;
    *len = 0;
    if (ctx->json && ctx->pretty) {
        FILE *mem = open_memstream(buf, len);
        if (mem) {
            ctx->out = mem;
        }
    }
    if (ctx->json) {
        fputc('[', ctx->out);
    }
    return ctx->out;
}

static void ipJsonEnd(IpContext *ctx, char **buf, FILE *saved) {
    if (!ctx->json) {
        return;
    }
    fputc(']', ctx->out);
    if (ctx->out != saved) {
        fclose(ctx->out);
        ctx->out = saved;
        if (*buf) {
            ipJsonPretty(saved, *buf);
        }
        free(*buf);
        *buf = NULL;
    }
    fputc('\n', ctx->out);
}

static int ipShowLinks(IpContext *ctx, int argc, char **argv, bool link_object) {
    const char *dev = NULL;
    bool up_only = false;
    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "dev") == 0) {
            if (i + 1 >= argc) {
                fprintf(ctx->err, "Command line is not complete. Try option \"help\"\n");
                return 255;
            }
            dev = argv[++i];
        } else if (strcmp(arg, "up") == 0) {
            up_only = true;
        } else if (strcmp(arg, "scope") == 0 && !link_object && i + 1 < argc) {
            ++i; /* Every address is in a scope; the filter isn't kept. */
        } else if (!dev) {
            dev = arg;
        } else {
            fprintf(ctx->err, "Error: either \"dev\" is duplicate, or \"%s\" is a garbage.\n", arg);
            return 1;
        }
    }
    const PscalNetLink *only = NULL;
    if (dev) {
        only = pscalNetSnapshotFindLink(ctx->snap, dev);
        if (!only) {
            fprintf(ctx->err, "Device \"%s\" does not exist.\n", dev);
            return 1;
        }
    }
    char *buf;
    size_t len;
    FILE *saved;
    ipJsonBegin(ctx, &buf, &len, &saved);
    bool first_json = true;
    for (size_t i = 0; i < ctx->snap->link_count; ++i) {
        const PscalNetLink *link = &ctx->snap->links[i];
        if (only && link != only) {
            continue;
        }
        if (up_only && !(link->flags & IFF_UP)) {
            continue;
        }
        if (!link_object && !ipLinkHasFamily(ctx, link)) {
            continue;
        }
        ipShowOne(ctx, link, link_object, &first_json);
    }
    ipJsonEnd(ctx, &buf, saved);
    return 0;
}

/* The device a change names after "dev" (or, for link, first), so that a missing
 * one is reported before the refusal, as on Linux. */
static int ipCheckDev(IpContext *ctx, int argc, char **argv, bool bare_name) {
    for (int i = 0; i < argc; ++i) {
        const char *name = NULL;
        if (strcmp(argv[i], "dev") == 0 && i + 1 < argc) {
            name = argv[i + 1];
        } else if (bare_name && i == 0) {
            name = argv[0];
        }
        if (name && !pscalNetSnapshotFindLink(ctx->snap, name)) {
            fprintf(ctx->err, "Cannot find device \"%s\"\n", name);
            return 1;
        }
        if (name) {
            return 0;
        }
    }
    return -1;
}

static int ipAddress(IpContext *ctx, int argc, char **argv) {
    if (argc == 0 || ipMatches(argv[0], "show") || ipMatches(argv[0], "list") || strcmp(argv[0], "lst") == 0) {
        return ipShowLinks(ctx, argc ? argc - 1 : 0, argv + (argc ? 1 : 0), false);
    }
    const char *cmd = argv[0];
    if (ipMatches(cmd, "add") || ipMatches(cmd, "change") || strcmp(cmd, "chg") == 0 ||
        ipMatches(cmd, "replace") || ipMatches(cmd, "delete") || ipMatches(cmd, "flush")) {
        int rc = ipCheckDev(ctx, argc - 1, argv + 1, false);
        if (rc == -1) {
            fprintf(ctx->err, "Not enough information: \"dev\" argument is required.\n");
            return 1;
        }
        return rc != 0 ? rc : ipRefuse(ctx);
    }
    if (ipMatches(cmd, "help")) {
        fprintf(ctx->err,
                "Usage: ip address show [ dev IFNAME ] [ up ]\n"
                "       ip address {add|change|replace|del} IFADDR dev IFNAME\n"
                "       ip address flush dev IFNAME\n");
        return 255;
    }
    fprintf(ctx->err, "Command \"%s\" is unknown, try \"ip address help\".\n", cmd);
    return 255;
}

static int ipLink(IpContext *ctx, int argc, char **argv) {
    if (argc == 0 || ipMatches(argv[0], "show") || ipMatches(argv[0], "list") || strcmp(argv[0], "lst") == 0) {
        return ipShowLinks(ctx, argc ? argc - 1 : 0, argv + (argc ? 1 : 0), true);
    }
    const char *cmd = argv[0];
    if (ipMatches(cmd, "set") || ipMatches(cmd, "change") || ipMatches(cmd, "delete")) {
        int rc = ipCheckDev(ctx, argc - 1, argv + 1, true);
        if (rc == -1) {
            fprintf(ctx->err, "Not enough of information: \"dev\" argument is required.\n");
            return 255;
        }
        return rc != 0 ? rc : ipRefuse(ctx);
    }
    if (ipMatches(cmd, "add")) {
        return ipRefuse(ctx);
    }
    if (ipMatches(cmd, "help")) {
        fprintf(ctx->err,
                "Usage: ip link show [ [dev] DEVICE ] [ up ]\n"
                "       ip link set { DEVICE | dev DEVICE } [ { up | down } ] ...\n"
                "       ip link { add | delete } ...\n");
        return 255;
    }
    fprintf(ctx->err, "Command \"%s\" is unknown, try \"ip link help\".\n", cmd);
    return 255;
}

static void ipPrintRoute(IpContext *ctx, const PscalNetRoute *r, bool *first_json) {
    const PscalNetLink *link = pscalNetSnapshotLinkByIndex(ctx->snap, r->ifindex);
    const char *dev = link ? link->name : "?";
    char dst[INET6_ADDRSTRLEN + 8], buf[INET6_ADDRSTRLEN], gw[INET6_ADDRSTRLEN], src[INET6_ADDRSTRLEN];
    int full = r->family == AF_INET ? 32 : 128;
    if (r->dst_len == 0) {
        snprintf(dst, sizeof(dst), "default");
    } else if (r->dst_len == full) {
        snprintf(dst, sizeof(dst), "%s", ipFormatAddr(r->family, r->dst, buf, sizeof(buf)));
    } else {
        snprintf(dst, sizeof(dst), "%s/%d", ipFormatAddr(r->family, r->dst, buf, sizeof(buf)), r->dst_len);
    }
    if (r->has_gateway) {
        ipFormatAddr(r->family, r->gateway, gw, sizeof(gw));
    }
    if (r->has_src) {
        ipFormatAddr(r->family, r->src, src, sizeof(src));
    }
    bool on_link = !r->has_gateway;
    bool v6 = r->family == AF_INET6;
    unsigned metric = r->dst_len == 0 ? 1024 : 256;
    if (ctx->json) {
        FILE *out = ctx->out;
        bool f = true;
        if (!*first_json) {
            fputc(',', out);
        }
        *first_json = false;
        fputc('{', out);
        ipJsonKeyString(out, &f, "dst", dst);
        if (r->has_gateway) {
            ipJsonKeyString(out, &f, "gateway", gw);
        }
        ipJsonKeyString(out, &f, "dev", dev);
        if (r->kernel) {
            ipJsonKeyString(out, &f, "protocol", "kernel");
        }
        if (on_link && !v6) {
            ipJsonKeyString(out, &f, "scope", "link");
        }
        if (r->has_src) {
            ipJsonKeyString(out, &f, "prefsrc", src);
        }
        if (v6) {
            ipJsonKeyNumber(out, &f, "metric", metric);
        }
        ipJsonKey(out, &f, "flags");
        fputs("[]", out);
        if (v6) {
            ipJsonKeyString(out, &f, "pref", "medium");
        }
        fputc('}', out);
        return;
    }
    fprintf(ctx->out, "%s", dst);
    if (r->has_gateway) {
        fprintf(ctx->out, " via %s", gw);
    }
    fprintf(ctx->out, " dev %s", dev);
    if (r->kernel) {
        fprintf(ctx->out, " proto kernel");
    }
    if (on_link && !v6) {
        fprintf(ctx->out, " scope link");
    }
    if (r->has_src) {
        fprintf(ctx->out, " src %s", src);
    }
    if (v6) {
        fprintf(ctx->out, " metric %u pref medium", metric);
    }
    fputc('\n', ctx->out);
}

static bool ipPrefixContains(const PscalNetRoute *r, const unsigned char *addr) {
    int bits = r->dst_len;
    for (int i = 0; bits > 0; ++i, bits -= 8) {
        unsigned char mask = bits >= 8 ? 0xff : (unsigned char)(0xff << (8 - bits));
        if ((addr[i] & mask) != (r->dst[i] & mask)) {
            return false;
        }
    }
    return true;
}

static const PscalNetAddress *ipFirstAddress(const PscalNetLink *link, int family, bool global_first) {
    const PscalNetAddress *found = NULL;
    for (size_t i = 0; link && i < link->addr_count; ++i) {
        const PscalNetAddress *a = &link->addrs[i];
        if (a->family != family) {
            continue;
        }
        if (!global_first || strcmp(pscalNetAddressScope(family, a->addr), "global") == 0) {
            return a;
        }
        if (!found) {
            found = a;
        }
    }
    return found;
}

static int ipRouteGet(IpContext *ctx, int argc, char **argv) {
    const char *target = NULL;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "to") == 0) {
            continue;
        }
        target = argv[i];
        break;
    }
    if (!target) {
        fprintf(ctx->err, "need at least a destination address\n");
        return 1;
    }
    unsigned char addr[16] = {0};
    int family = AF_INET;
    if (inet_pton(AF_INET, target, addr) != 1) {
        family = AF_INET6;
        if (inet_pton(AF_INET6, target, addr) != 1) {
            fprintf(ctx->err, "Error: inet prefix is expected rather than \"%s\".\n", target);
            return 1;
        }
    }
    char buf[INET6_ADDRSTRLEN], other[INET6_ADDRSTRLEN];
    unsigned uid = (unsigned)getuid();
    /* One of the device's own addresses, or loopback's: the local table, through lo. */
    const PscalNetLink *lo = NULL;
    for (size_t i = 0; i < ctx->snap->link_count; ++i) {
        const PscalNetLink *link = &ctx->snap->links[i];
        if (link->flags & IFF_LOOPBACK) {
            lo = link;
        }
        for (size_t j = 0; j < link->addr_count; ++j) {
            if (link->addrs[j].family == family &&
                memcmp(link->addrs[j].addr, addr, family == AF_INET ? 4 : 16) == 0) {
                fprintf(ctx->out, "local %s dev %s src %s uid %u \n    cache <local> \n",
                        ipFormatAddr(family, addr, buf, sizeof(buf)), lo ? lo->name : "lo",
                        ipFormatAddr(family, addr, other, sizeof(other)), uid);
                return 0;
            }
        }
    }
    if (family == AF_INET && addr[0] == 127) {
        fprintf(ctx->out, "local %s dev lo src 127.0.0.1 uid %u \n    cache <local> \n",
                ipFormatAddr(family, addr, buf, sizeof(buf)), uid);
        return 0;
    }
    const PscalNetRoute *best = NULL;
    for (size_t i = 0; i < ctx->snap->route_count; ++i) {
        const PscalNetRoute *r = &ctx->snap->routes[i];
        if (r->family == family && ipPrefixContains(r, addr) && (!best || r->dst_len > best->dst_len)) {
            best = r;
        }
    }
    if (!best) {
        fprintf(ctx->err, "RTNETLINK answers: Network is unreachable\n");
        return 2;
    }
    const PscalNetLink *link = pscalNetSnapshotLinkByIndex(ctx->snap, best->ifindex);
    const PscalNetAddress *src = ipFirstAddress(link, family, family == AF_INET6);
    fprintf(ctx->out, "%s", ipFormatAddr(family, addr, buf, sizeof(buf)));
    if (family == AF_INET6) {
        fprintf(ctx->out, " from ::");
    }
    if (best->has_gateway) {
        fprintf(ctx->out, " via %s", ipFormatAddr(family, best->gateway, other, sizeof(other)));
    }
    fprintf(ctx->out, " dev %s", link ? link->name : "?");
    if (src) {
        fprintf(ctx->out, " src %s", ipFormatAddr(family, src->addr, other, sizeof(other)));
    }
    if (family == AF_INET6) {
        fprintf(ctx->out, " metric %u pref medium\n", best->dst_len == 0 ? 1024u : 256u);
    } else {
        fprintf(ctx->out, " uid %u \n    cache \n", uid);
    }
    return 0;
}

static int ipRoute(IpContext *ctx, int argc, char **argv) {
    int family = ctx->family == AF_INET6 ? AF_INET6 : AF_INET;
    if (argc > 0 && ipMatches(argv[0], "get")) {
        return ipRouteGet(ctx, argc - 1, argv + 1);
    }
    if (argc > 0 && !(ipMatches(argv[0], "show") || ipMatches(argv[0], "list") || strcmp(argv[0], "lst") == 0)) {
        const char *cmd = argv[0];
        if (ipMatches(cmd, "add") || ipMatches(cmd, "change") || ipMatches(cmd, "replace") ||
            ipMatches(cmd, "prepend") || ipMatches(cmd, "append") || ipMatches(cmd, "delete") ||
            ipMatches(cmd, "flush") || ipMatches(cmd, "test")) {
            int rc = ipCheckDev(ctx, argc - 1, argv + 1, false);
            return rc > 0 ? rc : ipRefuse(ctx);
        }
        if (ipMatches(cmd, "help")) {
            fprintf(ctx->err,
                    "Usage: ip route [ list ] [ dev IFNAME ] [ default ]\n"
                    "       ip route get ADDRESS\n"
                    "       ip route { add | del | change | append | replace } ROUTE\n");
            return 255;
        }
        fprintf(ctx->err, "Command \"%s\" is unknown, try \"ip route help\".\n", cmd);
        return 255;
    }
    if (argc > 0) {
        argc--;
        argv++;
    }
    const PscalNetLink *only = NULL;
    bool default_only = false;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "dev") == 0 || strcmp(argv[i], "oif") == 0) {
            if (i + 1 >= argc) {
                fprintf(ctx->err, "Command line is not complete. Try option \"help\"\n");
                return 255;
            }
            only = pscalNetSnapshotFindLink(ctx->snap, argv[++i]);
            if (!only) {
                fprintf(ctx->err, "Cannot find device \"%s\"\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "default") == 0) {
            default_only = true;
        } else if (strcmp(argv[i], "table") == 0 && i + 1 < argc && strcmp(argv[i + 1], "main") == 0) {
            ++i;
        } else {
            fprintf(ctx->err, "Error: any valid prefix is expected rather than \"%s\".\n", argv[i]);
            return 1;
        }
    }
    char *buf;
    size_t len;
    FILE *saved;
    ipJsonBegin(ctx, &buf, &len, &saved);
    bool first_json = true;
    for (size_t i = 0; i < ctx->snap->route_count; ++i) {
        const PscalNetRoute *r = &ctx->snap->routes[i];
        if (r->family != family || (only && r->ifindex != only->index) || (default_only && r->dst_len != 0)) {
            continue;
        }
        ipPrintRoute(ctx, r, &first_json);
    }
    ipJsonEnd(ctx, &buf, saved);
    return 0;
}

int smallclueIpRun(int argc, char **argv, const void *snapshot, FILE *out, FILE *err) {
    IpContext ctx = {AF_UNSPEC, false, false, false, false, snapshot, out, err};
    int i = 1;
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; ++i) {
        const char *opt = argv[i] + 1;
        if (opt[0] == '-') {
            opt++;
        }
        if (strcmp(opt, "4") == 0) {
            ctx.family = AF_INET;
        } else if (strcmp(opt, "6") == 0) {
            ctx.family = AF_INET6;
        } else if (strcmp(opt, "0") == 0) {
            ctx.family = IP_FAMILY_LINK;
        } else if (strlen(opt) >= 2 && ipMatches(opt, "brief")) {
            ctx.brief = true;
        } else if (ipMatches(opt, "json")) {
            ctx.json = true;
        } else if (ipMatches(opt, "pretty")) {
            ctx.pretty = true;
        } else if (ipMatches(opt, "oneline")) {
            ctx.oneline = true;
        } else if (ipMatches(opt, "family")) {
            if (i + 1 >= argc) {
                return ipUsage(&ctx);
            }
            const char *f = argv[++i];
            if (strcmp(f, "inet") == 0) {
                ctx.family = AF_INET;
            } else if (strcmp(f, "inet6") == 0) {
                ctx.family = AF_INET6;
            } else if (strcmp(f, "link") == 0) {
                ctx.family = IP_FAMILY_LINK;
            } else {
                fprintf(err, "Error: argument \"%s\" is wrong: invalid protocol family\n", f);
                return 255;
            }
        } else if (ipMatches(opt, "help")) {
            return ipUsage(&ctx);
        } else {
            fprintf(err, "Option \"%s\" is unknown, try \"ip -help\".\n", argv[i]);
            return 255;
        }
    }
    if (i >= argc) {
        return ipUsage(&ctx);
    }
    const char *object = argv[i];
    int rest = argc - i - 1;
    char **rest_argv = argv + i + 1;
    /* iproute2's order, so one letter means what it means there. */
    if (ipMatches(object, "address")) {
        return ipAddress(&ctx, rest, rest_argv);
    }
    if (ipMatches(object, "route")) {
        return ipRoute(&ctx, rest, rest_argv);
    }
    if (ipMatches(object, "link")) {
        return ipLink(&ctx, rest, rest_argv);
    }
    if (ipMatches(object, "help")) {
        return ipUsage(&ctx);
    }
    fprintf(err, "Object \"%s\" is unknown, try \"ip help\".\n", object);
    return 255;
}

int smallclueIpCommand(int argc, char **argv) {
    PscalNetSnapshot snap;
    if (!pscalNetSnapshotTake(&snap)) {
        fprintf(stderr, "Cannot open netlink socket: Operation not permitted\n");
        pscalNetSnapshotFree(&snap);
        return 1;
    }
    int rc = smallclueIpRun(argc, argv, &snap, stdout, stderr);
    fflush(stdout);
    pscalNetSnapshotFree(&snap);
    return rc;
}

#endif /* PSCAL_TARGET_IOS */
