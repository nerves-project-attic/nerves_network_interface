/*
 *  Copyright 2017 Frank Hunleth
 *  Copyright 2014 LKC Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "netif_rtnetlink.h"
#include "util.h"
#include "netif.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <libmnl/libmnl.h>

// In Ubuntu 16.04, it seems that the new compat logic handling is preventing
// IFF_LOWER_UP from being defined properly. It looks like a bug, so define it
// here so that this file compiles.  A scan of all Nerves platforms and Ubuntu
// 16.04 has IFF_LOWER_UP always being set to 0x10000.
#define WORKAROUND_IFF_LOWER_UP (0x10000)

#define MAX_NETLINK_DEPTH 10

struct encode_state
{
    struct netif *nb;

    // Recursion level in RTNetlink message
    int level;

    // Keep track of how many kv pairs were added
    int count[MAX_NETLINK_DEPTH];

    // Holder for whether we're parsing an IPv4 or IPv6
    // Netlink message.
    int af_family;
};

struct nlattr_encoder_info;
typedef int (*nlattr_encoder)(struct encode_state *state, const char *key, const struct nlattr *tb);
typedef void (*nlattr_decoder)(const struct nlattr_encoder_info *info, struct netif *nb, struct nlmsghdr *nlh);
struct nlattr_encoder_info {
    unsigned int type;
    const char *name;
    nlattr_encoder encoder;
    nlattr_decoder decoder;
};

static void encode_state_push(struct encode_state *state)
{
    state->level++;
    if (state->level >= MAX_NETLINK_DEPTH)
        errx(EXIT_FAILURE, "RTNetlink recursion too deep!");

    state->count[state->level] = 0;
}

static int encode_state_pop(struct encode_state *state)
{
    int count = state->count[state->level];

    state->level--;
    if (state->level < 0)
        errx(EXIT_FAILURE, "Programmer error parsing RTNetlink message!");

    return count;
}

static void encode_state_incr(struct encode_state *state)
{
    state->count[state->level]++;
}

static int encode_kv_stats(struct netif *nb, const char *key, const struct nlattr *attr)
{
    struct rtnl_link_stats *stats = (struct rtnl_link_stats *) mnl_attr_get_payload(attr);

    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_map_header(nb->resp, &nb->resp_index, 10);
    encode_kv_ulong(nb, "rx_packets", stats->rx_packets);
    encode_kv_ulong(nb, "tx_packets", stats->tx_packets);
    encode_kv_ulong(nb, "rx_bytes", stats->rx_bytes);
    encode_kv_ulong(nb, "tx_bytes", stats->tx_bytes);
    encode_kv_ulong(nb, "rx_errors", stats->rx_errors);
    encode_kv_ulong(nb, "tx_errors", stats->tx_errors);
    encode_kv_ulong(nb, "rx_dropped", stats->rx_dropped);
    encode_kv_ulong(nb, "tx_dropped", stats->tx_dropped);
    encode_kv_ulong(nb, "multicast", stats->multicast);
    encode_kv_ulong(nb, "collisions", stats->collisions);

    return 0;
}

static int encode_kv_operstate(struct netif *nb, const char *key, int operstate)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);

    // Refer to RFC2863 for state descriptions (or the kernel docs)
    const char *operstate_atom;
    switch (operstate) {
    default:
    case IF_OPER_UNKNOWN:        operstate_atom = "unknown"; break;
    case IF_OPER_NOTPRESENT:     operstate_atom = "notpresent"; break;
    case IF_OPER_DOWN:           operstate_atom = "down"; break;
    case IF_OPER_LOWERLAYERDOWN: operstate_atom = "lowerlayerdown"; break;
    case IF_OPER_TESTING:        operstate_atom = "testing"; break;
    case IF_OPER_DORMANT:        operstate_atom = "dormant"; break;
    case IF_OPER_UP:             operstate_atom = "up"; break;
    }
    ei_encode_atom(nb->resp, &nb->resp_index, operstate_atom);

    return 0;
}

#ifdef DECODE_AF_SPEC // Not supported yet.
static int encode_af_inet_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;

    // Skip unsupported attributes in user-space
    if (mnl_attr_type_valid(attr, IFLA_INET_MAX) < 0)
        return MNL_CB_OK;

    return MNL_CB_OK;
}

static int encode_af_inet6_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;

    // Skip unsupported attributes in user-space
    if (mnl_attr_type_valid(attr, IFLA_INET6_MAX) < 0)
        return MNL_CB_OK;

    return MNL_CB_OK;
}

static int encode_af_spec_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    struct netif *nb = state->nb;

    mnl_attr_cb_t cb;

    switch (mnl_attr_get_type(attr)) {
    case AF_INET:
        ei_encode_atom(nb->resp, &nb->resp_index, "af_inet");
        cb = encode_af_inet_attrs;
        break;

    case AF_INET6:
        ei_encode_atom(nb->resp, &nb->resp_index, "af_inet6");
        cb = encode_af_inet6_attrs;
        break;

    default:
        debug("encode_af_spec_attrs: skipping %d", mnl_attr_get_type(attr));
        return MNL_CB_OK;
    }

    encode_state_incr(state);

    int map_count_index = nb->resp_index;
    ei_encode_map_header(nb->resp, &nb->resp_index, 0);

    encode_state_push(state);
    int rc = mnl_attr_parse_nested(attr, cb, state);
    int count = encode_state_pop(state);

    ei_encode_map_header(nb->resp, &map_count_index, count);

    return rc;
}
#endif

static int nlattr_encode_string(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_string(state->nb, name, mnl_attr_get_str(tb));
    return MNL_CB_OK;
}
void nlattr_decode_string(const struct nlattr_encoder_info *info, struct netif *nb, struct nlmsghdr *nlh)
{
    char temp[128];
    if (erlcmd_decode_string(nb->req, &nb->req_index, temp, sizeof(temp)) < 0)
        errx(EXIT_FAILURE, "Expecting string for %s", info->name);
    mnl_attr_put_strz(nlh, info->type, temp);
}
static int nlattr_encode_macaddr(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_macaddr(state->nb, name, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
void nlattr_decode_macaddr(const struct nlattr_encoder_info *info, struct netif *nb, struct nlmsghdr *nlh)
{
    char temp[128];
    unsigned char mac[6];
    if (erlcmd_decode_string(nb->req, &nb->req_index, temp, sizeof(temp)) < 0 ||
           string_to_macaddr(temp, mac) < 0)
        errx(EXIT_FAILURE, "Expecting macaddr string for %s", info->name);
    mnl_attr_put(nlh, info->type, sizeof(mac), mac);
}
static int nlattr_encode_ulong(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_ulong(state->nb, name, mnl_attr_get_u32(tb));
    return MNL_CB_OK;
}
void nlattr_decode_ulong(const struct nlattr_encoder_info *info, struct netif *nb, struct nlmsghdr *nlh)
{
    unsigned long temp;
    if (ei_decode_ulong(nb->req, &nb->req_index, &temp) < 0)
        errx(EXIT_FAILURE, "Expecting unsigned long for %s", info->name);
    mnl_attr_put_u32(nlh, info->type, temp);
}
static int nlattr_encode_uchar(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_ulong(state->nb, name, mnl_attr_get_u8(tb));
    return MNL_CB_OK;
}
static int nlattr_encode_operstate(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_operstate(state->nb, name, mnl_attr_get_u32(tb));
    return MNL_CB_OK;
}
static int nlattr_encode_stats(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_stats(state->nb, name, tb);
    return MNL_CB_OK;
}
static int nlattr_encode_ipaddress(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    encode_kv_ipaddress(state->nb, name, state->af_family, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
void nlattr_decode_ipaddress(const struct nlattr_encoder_info *info, struct netif *nb, struct nlmsghdr *nlh)
{
    char ipaddr_str[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr_str, sizeof(ipaddr_str)) < 0)
        errx(EXIT_FAILURE, "Expecting IP address string for %s", info->name);

    // Try IPv4 conversion
    struct in_addr ipv4addr;
    if (inet_pton(AF_INET, ipaddr_str, &ipv4addr) > 0) {
        mnl_attr_put(nlh, info->type, sizeof(ipv4addr), &ipv4addr);
        return;
    }

    // If that didn't work, try IPv6 conversion
    struct in6_addr ipv6addr;
    if (inet_pton(AF_INET6, ipaddr_str, &ipv6addr) > 0) {
        mnl_attr_put(nlh, info->type, sizeof(ipv6addr), &ipv6addr);
        return;
    }

    errx(EXIT_FAILURE, "Couldn't convert '%s' to an IPv4 or IPv6 address", ipaddr_str);
}

#ifdef DECODE_AF_SPEC
static int nlattr_encode_af_spec(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    struct netif *nb = state->nb;

    ei_encode_atom(nb->resp, &nb->resp_index, name);

    int map_count_index = nb->resp_index;
    ei_encode_map_header(nb->resp, &nb->resp_index, 0);

    encode_state_push(state);
    int rc = mnl_attr_parse_nested(tb, encode_af_spec_attrs, state);
    int count = encode_state_pop(state);

    ei_encode_map_header(nb->resp, &map_count_index, count);

    return rc;
}
#endif
static int nlattr_encode_wireless(struct encode_state *state, const char *name, const struct nlattr *tb)
{
    struct iw_event *iw = mnl_attr_get_payload(tb);
    uint16_t iw_len = mnl_attr_get_payload_len(tb);

    if (iw->len > iw_len) {
        debug("wireless len longer than expected: %d vs %d", iw->len, iw_len);

        // Ignore -> maybe a weird WiFi driver issue?
        encode_kv_atom(state->nb, name, "error");
        return MNL_CB_OK;
    }

    // Encode ioctl with value as a tuple.
    ei_encode_atom(state->nb->resp, &state->nb->resp_index, name);
    ei_encode_tuple_header(state->nb->resp, &state->nb->resp_index, 2);
    switch (iw->cmd) {
    case SIOCGIWSCAN: /* get scanning results */
        encode_kv_binary(state->nb, "siocgiwscan", &iw->u, iw->len - 4);
        break;

    case SIOCGIWAP:   /* get access point MAC addresses */
        encode_kv_macaddr(state->nb, "siocgiwap", (unsigned char *) iw->u.ap_addr.sa_data);
        break;

    case IWEVASSOCRESPIE:
        encode_kv_binary(state->nb, "iwevassocrespie", &iw->u, iw->len - 4);
        break;

    default:
        debug("wireless: unhandled ioctl 0x%04x", iw->cmd);
        ei_encode_ulong(state->nb->resp, &state->nb->resp_index, iw->cmd);
        ei_encode_binary(state->nb->resp, &state->nb->resp_index, &iw->u, iw->len - 4);
    }
    return MNL_CB_OK;
}

const struct nlattr_encoder_info *nlattr_find_by_type(const struct nlattr_encoder_info *table, unsigned int type)
{
    const struct nlattr_encoder_info *info;
    for (info = table;
         info->name != NULL;
         info++) {
        if (info->type == type)
            return info;
    }
    return info;
}
const struct nlattr_encoder_info *nlattr_find_by_name(const struct nlattr_encoder_info *table, const char *str)
{
    const struct nlattr_encoder_info *info;
    for (info = table;
         info->name != NULL;
         info++) {
        if (strcmp(info->name, str) == 0)
            return info;
    }
    return info;
}

static const struct nlattr_encoder_info ifla_encoders[] = {
    { IFLA_MTU, "mtu", nlattr_encode_ulong, nlattr_decode_ulong},
    { IFLA_IFNAME, "ifname", nlattr_encode_string, nlattr_decode_string},
    { IFLA_ADDRESS, "mac_address", nlattr_encode_macaddr, nlattr_decode_macaddr},
    { IFLA_BROADCAST, "mac_broadcast", nlattr_encode_macaddr, nlattr_decode_macaddr},
    { IFLA_LINK, "link", nlattr_encode_ulong, nlattr_decode_ulong},
    { IFLA_OPERSTATE, "operstate", nlattr_encode_operstate, NULL},
    { IFLA_STATS, "stats", nlattr_encode_stats, NULL},
#ifdef DECODE_AF_SPEC
    { IFLA_AF_SPEC, "af_spec", ifla_encode_af_spec, NULL},
#endif
    { IFLA_WIRELESS, "wireless", nlattr_encode_wireless, NULL},
    { 0, NULL, NULL, NULL }
};
static const struct nlattr_encoder_info ifa_encoders[] = {
    { IFA_ADDRESS, "address", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { IFA_LOCAL, "local", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { IFA_LABEL, "label", nlattr_encode_string, nlattr_decode_string},
    { IFA_BROADCAST, "broadcast", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { IFA_ANYCAST, "anycast", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    //{ IFA_CACHEINFO, "cacheinfo", nlattr_encode_operstate},
    //{ IFA_MULTICAST, "multicast", nlattr_encode_stats},
    //{ IFA_FLAGS, "flags", ifla_encode_ulong},
    { 0, NULL, NULL, NULL }
};
static const struct nlattr_encoder_info rta_encoders[] = {
    { RTA_DST, "dst", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { RTA_SRC, "src", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { RTA_IIF, "iif", nlattr_encode_ulong, nlattr_decode_ulong},
    { RTA_OIF, "oif", nlattr_encode_ulong, nlattr_decode_ulong},
    { RTA_GATEWAY, "gateway", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    { RTA_PRIORITY, "priority", nlattr_encode_ulong, nlattr_decode_ulong},
    { RTA_PREFSRC, "prefsrc", nlattr_encode_ipaddress, nlattr_decode_ipaddress},
    //{ RTA_TABLE, "table", nlattr_encode_ulong, nlattr_decode_ulong}, // In message header, so ignore here
    { RTA_PREF, "pref", nlattr_encode_uchar, NULL},
    { RTA_MARK, "mark", nlattr_encode_ulong, nlattr_decode_ulong},
    //{ RTA_METRICS, "metrics", ifla_encode_ulong, nlattr_decode_ulong},
    //{ RTA_MULTIPATH, "multipath", ?ifla_encode_ulong, nlattr_decode_ulong},
    //{ RTA_FLOW, "xresolve", ?ifla_encode_ulong, nlattr_decode_ulong},
    { 0, NULL, NULL, NULL }
};

static int encode_rtm_link_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    int type = mnl_attr_get_type(attr);
    int rc = MNL_CB_OK;

    // Handle known attributes
    const struct nlattr_encoder_info *info =
            nlattr_find_by_type(ifla_encoders, type);
    if (mnl_attr_type_valid(attr, IFLA_MAX) >= 0 && info->encoder) {
        encode_state_incr(state);
        rc = info->encoder(state, info->name, attr);
    }

    return rc;
}
static void decode_rtm_link_attrs(struct netif *nb, const char *name, struct nlmsghdr *nlh)
{
    const struct nlattr_encoder_info *info =
            nlattr_find_by_name(ifla_encoders, name);
    if (info->decoder) {
        info->decoder(info, nb, nlh);
    } else {
        errx(EXIT_FAILURE, "Can't find decoder for '%s'", name);
    }
}

static int encode_rtm_addr_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    uint16_t type = mnl_attr_get_type(attr);
    int rc = MNL_CB_OK;

    // Handle known attributes
    const struct nlattr_encoder_info *info =
            nlattr_find_by_type(ifa_encoders, type);
    if (mnl_attr_type_valid(attr, IFA_MAX) >= 0 && info->encoder) {
        encode_state_incr(state);
        rc = info->encoder(state, info->name, attr);
    }

    return rc;
}
static void decode_rtm_addr_attrs(struct netif *nb, const char *name, struct nlmsghdr *nlh)
{
    const struct nlattr_encoder_info *info =
            nlattr_find_by_name(ifa_encoders, name);
    if (info->decoder) {
        info->decoder(info, nb, nlh);
    } else {
        errx(EXIT_FAILURE, "Can't find decoder for '%s'", name);
    }
}

static int encode_rtm_route_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    uint16_t type = mnl_attr_get_type(attr);
    int rc = MNL_CB_OK;

    // Handle known attributes
    const struct nlattr_encoder_info *info =
            nlattr_find_by_type(rta_encoders, type);
    if (mnl_attr_type_valid(attr, RTA_MAX) >= 0 && info->encoder) {
        encode_state_incr(state);
        rc = info->encoder(state, info->name, attr);
    }

    return rc;
}
static void decode_rtm_route_attrs(struct netif *nb, const char *name, struct nlmsghdr *nlh)
{
    const struct nlattr_encoder_info *info =
            nlattr_find_by_name(rta_encoders, name);
    if (info->decoder) {
        info->decoder(info, nb, nlh);
    } else {
        errx(EXIT_FAILURE, "Can't find decoder for '%s'", name);
    }
}

struct nl_typestring {
    unsigned int type;
    const char *str;
};
static const char *nl_typestring_to_string(const struct nl_typestring *strings, unsigned int type)
{
    for (const struct nl_typestring *pair = strings; pair->str != NULL; pair++) {
        if (pair->type == type)
            return pair->str;
    }
    return "unknown";
}
static unsigned int nl_typestring_to_int(const struct nl_typestring *strings, const char *str)
{
    for (const struct nl_typestring *pair = strings; pair->str != NULL; pair++) {
        if (strcmp(str, pair->str) == 0)
            return pair->type;
    }
    return 0;
}

static struct nl_typestring nlmsg_type_strings[] = {
    { RTM_NEWLINK, "newlink" },
    { RTM_DELLINK, "dellink" },
    { RTM_NEWADDR, "newaddr" },
    { RTM_DELADDR, "deladdr" },
    { RTM_NEWROUTE, "newroute" },
    { RTM_DELROUTE, "delroute" },
    { RTM_NEWNEIGH, "newneigh" },
    { RTM_DELNEIGH, "delneigh" },
    { RTM_NEWRULE, "newrule" },
    { RTM_DELRULE, "delrule" },
    { RTM_NEWQDISC, "newqdisc" },
    { RTM_DELQDISC, "delqdisc" },
    { RTM_NEWTCLASS, "newtclass" },
    { RTM_DELTCLASS, "deltclass" },
    { RTM_NEWTFILTER, "newtfilter" },
    { RTM_DELTFILTER, "deltfilter" },
    { 0, NULL}
};
static struct nl_typestring ifi_type_strings[] = {
    { ARPHRD_ETHER, "ethernet" },
    { 0, NULL}
};
static struct nl_typestring rtm_type_strings[] = {
    { RTN_UNSPEC, "unspec" },
    { RTN_UNICAST, "unicast" },
    { RTN_LOCAL, "local" },
    { RTN_BROADCAST, "broadcast" },
    { RTN_ANYCAST, "anycast" },
    { RTN_MULTICAST, "multicast" },
    { RTN_BLACKHOLE, "blackhole" },
    { RTN_UNREACHABLE, "unreachable" },
    { RTN_PROHIBIT, "prohibit" },
    { RTN_THROW, "throw" },
    { RTN_NAT, "nat" },
    { RTN_XRESOLVE, "xresolve" },
    { 0, NULL}
};
static struct nl_typestring rtm_protocol_strings[] = {
    { RTPROT_UNSPEC, "unknown" },
    { RTPROT_REDIRECT, "redirect" },
    { RTPROT_KERNEL, "kernel" },
    { RTPROT_BOOT, "boot" },
    { RTPROT_STATIC, "static" },
    { 0, NULL}
};

static struct nl_typestring rtm_scope_strings[] = {
    { RT_SCOPE_UNIVERSE, "universe" },
    { RT_SCOPE_SITE, "site" },
    { RT_SCOPE_LINK, "link" },
    { RT_SCOPE_HOST, "host" },
    { RT_SCOPE_NOWHERE, "nowhere" },
    { 0, NULL}
};

static struct nl_typestring rtm_table_strings[] = {
    { RT_TABLE_UNSPEC, "unspec" },
    { RT_TABLE_DEFAULT, "default" },
    { RT_TABLE_MAIN, "main" },
    { RT_TABLE_LOCAL, "local" },
    { 0, NULL}
};
static struct nl_typestring ifa_family_strings[] = {
    { AF_UNSPEC, "af_unspec"},
    { AF_INET, "af_inet"},
    { AF_INET6, "af_inet6"},
    { 0, NULL}
};

static const char *nlmsg_type_to_string(unsigned short nlmsg_type)
{
    return nl_typestring_to_string(nlmsg_type_strings, nlmsg_type);
}
static unsigned short nlmsg_type_to_int(const char *str)
{
    return nl_typestring_to_int(nlmsg_type_strings, str);
}

static const char *ifi_type_to_string(unsigned short ifi_type)
{
    return nl_typestring_to_string(ifi_type_strings, ifi_type);
}
static unsigned short ifi_type_to_int(const char *str)
{
    return nl_typestring_to_int(ifi_type_strings, str);
}

static const char *rtm_type_to_string(unsigned char rtm_type)
{
    return nl_typestring_to_string(rtm_type_strings, rtm_type);
}
static unsigned char rtm_type_to_int(const char *str)
{
    return nl_typestring_to_int(rtm_type_strings, str);
}

static const char *rtm_protocol_to_string(unsigned char rtm_protocol)
{
    return nl_typestring_to_string(rtm_protocol_strings, rtm_protocol);
}
static unsigned char rtm_protocol_to_int(const char *str)
{
    return nl_typestring_to_int(rtm_protocol_strings, str);
}

static const char *rtm_scope_to_string(unsigned char rtm_scope)
{
    return nl_typestring_to_string(rtm_scope_strings, rtm_scope);
}
static unsigned char rtm_scope_to_int(const char *str)
{
    return nl_typestring_to_int(rtm_scope_strings, str);
}

static const char *rtm_table_to_string(unsigned char rtm_table)
{
    return nl_typestring_to_string(rtm_table_strings, rtm_table);
}
static unsigned char rtm_table_to_int(const char *str)
{
    return nl_typestring_to_int(rtm_table_strings, str);
}

static const char *ifa_family_to_string(unsigned char fam)
{
    return nl_typestring_to_string(ifa_family_strings, fam);
}
static unsigned char ifa_family_to_int(const char *str)
{
    return nl_typestring_to_int(ifa_family_strings, str);
}
static void dump_binary(const char *what, const unsigned char *buffer, size_t len)
{
    fprintf(stderr, "\r\n%s = <<", what);
    int chars = 2;
    for (size_t i = 0; i < len; i++) {
        chars += fprintf(stderr, "%d%s", buffer[i], i != len - 1 ? ", " : "");
        if (chars >= 70 && i != len - 1) {
            fprintf(stderr, "\r\n  ");
            chars = 2;
        }
    }
    fprintf(stderr, ">>\r\n");
}

static int netif_encode_rtnetlink(const struct nlmsghdr *nlh, void *data)
{
    struct encode_state *state = data;
    struct netif *nb = state->nb;

    debug("netif_encode_rtnetlink: %s", nlmsg_type_to_string(nlh->nlmsg_type));

    encode_state_incr(state);
    encode_state_push(state);

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);
    ei_encode_atom(nb->resp, &nb->resp_index, nlmsg_type_to_string(nlh->nlmsg_type));

    // Add a map header, but don't fill in the count field until the end when we know it.
    int map_count_index = nb->resp_index;
    ei_encode_map_header(nb->resp, &nb->resp_index, 0);

    // See "man 7 rtnetlink" for documentation on interpreting netlink messages.
    // The next best place is the Linux kernel.
    mnl_attr_cb_t cb = NULL;
    unsigned int offset = 0;

    switch (nlh->nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
    {
        cb = encode_rtm_link_attrs;
        offset = sizeof(struct ifinfomsg);

        const struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
        encode_kv_long(nb, "index", ifm->ifi_index);
        encode_kv_atom(nb, "type", ifi_type_to_string(ifm->ifi_type));

        encode_kv_bool(nb, "is_up", ifm->ifi_flags & IFF_UP);
        encode_kv_bool(nb, "is_broadcast", ifm->ifi_flags & IFF_BROADCAST);
        encode_kv_bool(nb, "is_running", ifm->ifi_flags & IFF_RUNNING);
        encode_kv_bool(nb, "is_lower_up", ifm->ifi_flags & WORKAROUND_IFF_LOWER_UP);
        encode_kv_bool(nb, "is_multicast", ifm->ifi_flags & IFF_MULTICAST);
        state->count[state->level] += 7;
        break;
    }

    case RTM_NEWADDR:
    case RTM_DELADDR:
    {
        const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
        debug("RTM_NEWADDR/DELADDR: family=%s, index=%d, scope=%d, prefixlen=%d\n",
                ifa_family_to_string(ifa->ifa_family),
                ifa->ifa_index,
                ifa->ifa_scope,
                ifa->ifa_prefixlen);

        encode_kv_long(nb, "index", ifa->ifa_index);
        encode_kv_atom(nb, "family", ifa_family_to_string(ifa->ifa_family));
        encode_kv_ulong(nb, "scope", ifa->ifa_scope);
        encode_kv_ulong(nb, "prefixlen", ifa->ifa_prefixlen);

        state->af_family = ifa->ifa_family;
        state->count[state->level] += 4;
        cb = encode_rtm_addr_attrs;
        offset = sizeof(struct ifaddrmsg);
        break;
    }

    case RTM_NEWROUTE:
    case RTM_DELROUTE:
    {

        const struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
        debug("RTM_NEWROUTE/DELROUTE: family=%s, dst_len=%d, src_len=%d, tos=%d, table=%d, protocol=%d, scope=%d, type=%d, flags=%d\n",
              ifa_family_to_string(rtm->rtm_family),
              rtm->rtm_dst_len,
              rtm->rtm_src_len,
              rtm->rtm_tos,
              rtm->rtm_table,
              rtm->rtm_protocol,
              rtm->rtm_scope,
              rtm->rtm_type,
              rtm->rtm_flags);

        encode_kv_atom(nb, "family", ifa_family_to_string(rtm->rtm_family));
        encode_kv_ulong(nb, "tos", rtm->rtm_tos);
        encode_kv_atom(nb, "table", rtm_table_to_string(rtm->rtm_table));
        encode_kv_atom(nb, "protocol", rtm_protocol_to_string(rtm->rtm_protocol));
        encode_kv_atom(nb, "scope", rtm_scope_to_string(rtm->rtm_scope));
        encode_kv_atom(nb, "type", rtm_type_to_string(rtm->rtm_type));

        state->af_family = rtm->rtm_family;
        state->count[state->level] += 6;
        cb = encode_rtm_route_attrs;
        offset = sizeof(struct rtmsg);
        break;
    }

    default:
        debug("Need to add %d!", nlh->nlmsg_type);
        encode_state_pop(state);
        return MNL_CB_OK;
    }

    if (cb) {
        if (mnl_attr_parse(nlh, offset, cb, state) != MNL_CB_OK) {
            debug("Error from mnl_attr_parse");
            return MNL_CB_ERROR;
        }
    }
    // Go back and write the number of entries in the map.
    int count = encode_state_pop(state);
    ei_encode_map_header(nb->resp, &map_count_index, count);

    return MNL_CB_OK;
}

int handle_rtnetlink_notification(struct netif *nb, int bytecount)
{
    debug("handle_rtnetlink_notification %d bytes", bytecount);

    // Create the notification
    nb->resp_index = sizeof(uint16_t); // Skip over payload size
    nb->resp[nb->resp_index++] = 'n';
    ei_encode_version(nb->resp, &nb->resp_index);

    struct encode_state state;
    memset(&state, 0, sizeof(state));
    state.nb = nb;

    int list_index = nb->resp_index;
    ei_encode_list_header(nb->resp, &nb->resp_index, 1);

#if 0
    debug("mnl_nlmsg_fprintf{\n");
    mnl_nlmsg_fprintf(stderr, nb->nlbuf, bytecount, sizeof(struct ifinfomsg));
    debug("}mnl_nlmsg_fprintf\n");
#endif
    dump_binary("notif", (const unsigned char *) nb->nlbuf, bytecount);

    int rc = mnl_cb_run(nb->nlbuf, bytecount, 0, 0, netif_encode_rtnetlink, &state);
    if (rc == MNL_CB_STOP)
        warnx("mnl_cb_run stopped");
    else if (rc == MNL_CB_ERROR)
        warn("mnl_cb_run(handle_rtnetlink_notification)");

    // Only send the notification if there's something in the list.
    if (state.count[0] > 0) {
        nb->resp[nb->resp_index++] = ERL_NIL_EXT; // One would think there's be an ei_encode_nil..
        ei_encode_list_header(nb->resp, &list_index, state.count[0]);

        erlcmd_send(nb->resp, nb->resp_index);
    }

    return rc;
}

void process_ifm_attrs(struct netif *nb, struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
    memset(ifm, 0, sizeof(*ifm));
    ifm->ifi_family = AF_UNSPEC; // Currently unsettable

    int arity;
    if (ei_decode_list_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "expecting a list for ifm attributes");

    for (int i = 0; i < arity; i++) {
        int tuple_arity;
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &tuple_arity) < 0 ||
                tuple_arity != 2)
            errx(EXIT_FAILURE, "expecting a 2-tuple for the ifm attribute");

        char attr_type_str[20];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, attr_type_str, sizeof(attr_type_str)) < 0)
            errx(EXIT_FAILURE, "Expecting atom for ifm attribute type");

        if (strcmp(attr_type_str, "index") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            ifm->ifi_index = temp;
        } else if (strcmp(attr_type_str, "type") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            ifm->ifi_type = ifi_type_to_int(temp);
        } else if (strcmp(attr_type_str, "is_up") == 0) {
            int temp;
            ei_decode_boolean(nb->req, &nb->req_index, &temp);
            ifm->ifi_change |= IFF_UP;
            if (temp)
                ifm->ifi_flags |= IFF_UP;
        } else if (strcmp(attr_type_str, "is_broadcast") == 0) {
            int temp;
            ei_decode_boolean(nb->req, &nb->req_index, &temp);
            ifm->ifi_change |= IFF_BROADCAST;
            if (temp)
                ifm->ifi_flags |= IFF_BROADCAST;
        } else if (strcmp(attr_type_str, "is_running") == 0) {
            int temp;
            ei_decode_boolean(nb->req, &nb->req_index, &temp);
            ifm->ifi_change |= IFF_RUNNING;
            if (temp)
                ifm->ifi_flags |= IFF_RUNNING;
        } else if (strcmp(attr_type_str, "is_lower_up") == 0) {
            int temp;
            ei_decode_boolean(nb->req, &nb->req_index, &temp);
            ifm->ifi_change |= WORKAROUND_IFF_LOWER_UP;
            if (temp)
                ifm->ifi_flags |= WORKAROUND_IFF_LOWER_UP;
        } else if (strcmp(attr_type_str, "is_multicast") == 0) {
            int temp;
            ei_decode_boolean(nb->req, &nb->req_index, &temp);
            ifm->ifi_change |= IFF_MULTICAST;
            if (temp)
                ifm->ifi_flags |= IFF_MULTICAST;
        } else {
            decode_rtm_link_attrs(nb, attr_type_str, nlh);
        }
    }
}

void process_ifa_attrs(struct netif *nb, struct nlmsghdr *nlh)
{
    struct ifaddrmsg *ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
    memset(ifa, 0, sizeof(*ifa));

    int arity;
    if (ei_decode_list_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "expecting a list for ifa attrs");

    for (int i = 0; i < arity; i++) {
        int tuple_arity;
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &tuple_arity) < 0 ||
                tuple_arity != 2)
            errx(EXIT_FAILURE, "expecting a 2-tuple for the ifa attribute");

        char attr_type_str[20];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, attr_type_str, sizeof(attr_type_str)) < 0)
            errx(EXIT_FAILURE, "Expecting atom for ifa attribute type");

        if (strcmp(attr_type_str, "index") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            ifa->ifa_index = temp;
        } else if (strcmp(attr_type_str, "family") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            ifa->ifa_family = ifa_family_to_int(temp);
        } else if (strcmp(attr_type_str, "scope") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            ifa->ifa_scope = temp;
        } else if (strcmp(attr_type_str, "prefixlen") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            ifa->ifa_prefixlen = temp;
        } else {
            decode_rtm_addr_attrs(nb, attr_type_str, nlh);
        }
    }
}

void process_rtm_attrs(struct netif *nb, struct nlmsghdr *nlh)
{
    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    memset(rtm, 0, sizeof(*rtm));
    rtm->rtm_flags = 0; // not possible to set

    int arity;
    if (ei_decode_list_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "expecting a list for rtm");

    for (int i = 0; i < arity; i++) {
        int tuple_arity;
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &tuple_arity) < 0 ||
                tuple_arity != 2)
            errx(EXIT_FAILURE, "expecting a 2-tuple for the ifa attribute");

        char attr_type_str[20];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, attr_type_str, sizeof(attr_type_str)) < 0)
            errx(EXIT_FAILURE, "Expecting atom for ifa attribute type");

        if (strcmp(attr_type_str, "family") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            rtm->rtm_family = ifa_family_to_int(temp);
        } else if (strcmp(attr_type_str, "dst_len") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            rtm->rtm_dst_len = temp;
        } else if (strcmp(attr_type_str, "src_len") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            rtm->rtm_src_len = temp;
        } else if (strcmp(attr_type_str, "tos") == 0) {
            long temp;
            ei_decode_long(nb->req, &nb->req_index, &temp);
            rtm->rtm_tos = temp;
        } else if (strcmp(attr_type_str, "table") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            rtm->rtm_table = rtm_table_to_int(temp);
        } else if (strcmp(attr_type_str, "protocol") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            rtm->rtm_protocol = rtm_protocol_to_int(temp);
        } else if (strcmp(attr_type_str, "scope") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            rtm->rtm_scope = rtm_scope_to_int(temp);
        } else if (strcmp(attr_type_str, "type") == 0) {
            char temp[32];
            erlcmd_decode_atom(nb->req, &nb->req_index, temp, sizeof(temp));
            rtm->rtm_type = rtm_type_to_int(temp);
        } else {
            decode_rtm_route_attrs(nb, attr_type_str, nlh);
        }
    }
}


int send_rtnetlink_message(struct netif *nb)
{
    // TEMPORARY until re-written in Elixir

    char buf[2 * MNL_SOCKET_BUFFER_SIZE];
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);

    // Expecting a list of tuples
    // [{:newlink, [attributes]}, {:newroute, [attributes]}, ...]

    int arity;
    if (ei_decode_list_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "expecting a list");

    for (int i = 0; i < arity; i++) {
        int tuple_arity;
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &tuple_arity) < 0 ||
                tuple_arity != 2)
            errx(EXIT_FAILURE, "expecting a 2-tuple for the rtnetlink messages");

        char msg_type_str[20];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, msg_type_str, sizeof(msg_type_str)) < 0)
            errx(EXIT_FAILURE, "Expecting atom for rtnetlink message type");

        struct nlmsghdr *nlh = mnl_nlmsg_batch_current(batch);
        nlh->nlmsg_type = nlmsg_type_to_int(msg_type_str);
        nlh->nlmsg_flags = NLM_F_REQUEST; //  | NLM_F_ACK; Need an ACK???
        nlh->nlmsg_seq = nb->seq++;

        switch (nlh->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            process_ifm_attrs(nb, nlh);
            break;

        case RTM_NEWADDR:
        case RTM_DELADDR:
            process_ifa_attrs(nb, nlh);
            break;

        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            process_rtm_attrs(nb, nlh);
            break;

        default:
            errx(EXIT_FAILURE, "Need to add %d!", nlh->nlmsg_type);
            break;

        }

        if (!mnl_nlmsg_batch_next(batch))
            errx(EXIT_FAILURE, "netlink message was too long");
    }

    if (mnl_socket_sendto(nb->nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
        err(EXIT_FAILURE, "mnl_socket_sendto");

    mnl_nlmsg_batch_stop(batch);
    return 0;
}
