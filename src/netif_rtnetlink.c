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

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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

static void encode_kv_stats(struct netif *nb, const char *key, const struct nlattr *attr)
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
}

static void encode_kv_operstate(struct netif *nb, int operstate)
{
    ei_encode_atom(nb->resp, &nb->resp_index, "operstate");

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

static int ifla_encode_mtu(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ulong(state->nb, "mtu", mnl_attr_get_u32(tb));
    return MNL_CB_OK;
}
static int ifla_encode_ifname(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_string(state->nb, "ifname", mnl_attr_get_str(tb));
    return MNL_CB_OK;
}
static int ifla_encode_address(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_macaddr(state->nb, "mac_address", mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
static int ifla_encode_broadcast(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_macaddr(state->nb, "mac_broadcast", mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
static int ifla_encode_link(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ulong(state->nb, "link", mnl_attr_get_u32(tb));
    return MNL_CB_OK;
}
static int ifla_encode_operstate(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_operstate(state->nb, mnl_attr_get_u32(tb));
    return MNL_CB_OK;
}
static int ifla_encode_stats(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_stats(state->nb, "stats", tb);
    return MNL_CB_OK;
}
#ifdef DECODE_AF_SPEC
static int ifla_encode_af_spec(struct encode_state *state, const struct nlattr *tb)
{
    struct netif *nb = state->nb;

    ei_encode_atom(nb->resp, &nb->resp_index, "ifla_af_spec");

    int map_count_index = nb->resp_index;
    ei_encode_map_header(nb->resp, &nb->resp_index, 0);

    encode_state_push(state);
    int rc = mnl_attr_parse_nested(tb, encode_af_spec_attrs, state);
    int count = encode_state_pop(state);

    ei_encode_map_header(nb->resp, &map_count_index, count);

    return rc;
}
#endif

typedef int (*ifla_encoder)(struct encode_state *state, const struct nlattr *tb);

static ifla_encoder ifla_encoders[IFLA_MAX + 1] = {
    [IFLA_MTU] = ifla_encode_mtu,
    [IFLA_IFNAME] = ifla_encode_ifname,
    [IFLA_ADDRESS] = ifla_encode_address,
    [IFLA_BROADCAST] = ifla_encode_broadcast,
    [IFLA_LINK] = ifla_encode_link,
    [IFLA_OPERSTATE] = ifla_encode_operstate,
    [IFLA_STATS] = ifla_encode_stats,
    #ifdef DECODE_AF_SPEC
    [IFLA_AF_SPEC] = ifla_encode_af_spec,
    #endif
};


static int encode_rtm_link_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    int type = mnl_attr_get_type(attr);
    int rc = MNL_CB_OK;

    // Handle known attributes
    if (mnl_attr_type_valid(attr, IFLA_MAX) >= 0 && ifla_encoders[type]) {
        encode_state_incr(state);
        rc = ifla_encoders[type](state, attr);
    }

    return rc;
}

static int ifa_encode_address(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ipaddress(state->nb, "address", state->af_family, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
static int ifa_encode_local(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ipaddress(state->nb, "local", state->af_family, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
static int ifa_encode_label(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_string(state->nb, "label", mnl_attr_get_str(tb));
    return MNL_CB_OK;
}
static int ifa_encode_broadcast(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ipaddress(state->nb, "broadcast", state->af_family, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}
static int ifa_encode_anycast(struct encode_state *state, const struct nlattr *tb)
{
    encode_kv_ipaddress(state->nb, "anycast", state->af_family, mnl_attr_get_payload(tb));
    return MNL_CB_OK;
}

static ifla_encoder ifa_encoders[IFA_MAX + 1] = {
    [IFA_ADDRESS] = ifa_encode_address,
    [IFA_LOCAL] = ifa_encode_local,
    [IFA_LABEL] = ifa_encode_label,
    [IFA_BROADCAST] = ifa_encode_broadcast,
    [IFA_ANYCAST] = ifa_encode_anycast,
    //[IFA_CACHEINFO] = ifa_encode_cacheinfo,
    //[IFA_MULTICAST] = ifa_encode_multicast,
    //[IFA_FLAGS] = ifa_encode_flags
};

static int encode_rtm_addr_attrs(const struct nlattr *attr, void *data)
{
    struct encode_state *state = data;
    int type = mnl_attr_get_type(attr);
    int rc = MNL_CB_OK;

    // Handle known attributes
    if (mnl_attr_type_valid(attr, IFA_MAX) >= 0 && ifa_encoders[type]) {
        encode_state_incr(state);
        rc = ifa_encoders[type](state, attr);
    }

    return rc;
}

static const char *ifa_family_to_string(unsigned char family)
{
    switch (family) {
    case AF_INET: return "af_inet";
    case AF_INET6: return "af_inet6";
    default: return "af_other";
    }
}

static const char *ifi_type_to_string(unsigned short ifi_type)
{
    switch (ifi_type) {
    case ARPHRD_ETHER: return "ethernet";
    default: return "other";
    }
}

static const char *nlmsg_type_to_string(unsigned short nlmsg_type)
{
    switch (nlmsg_type) {
    case RTM_NEWLINK: return "newlink";
    case RTM_DELLINK: return "dellink";
    case RTM_NEWADDR: return "newaddr";
    case RTM_DELADDR: return "deladdr";
    case RTM_NEWROUTE: return "newroute";
    case RTM_DELROUTE: return "delroute";
    case RTM_NEWNEIGH: return "newneigh";
    case RTM_DELNEIGH: return "delneigh";
    case RTM_NEWRULE: return "newrule";
    case RTM_DELRULE: return "delrule";
    case RTM_NEWQDISC: return "newqdisc";
    case RTM_DELQDISC: return "delqdisc";
    case RTM_NEWTCLASS: return "newtclass";
    case RTM_DELTCLASS: return "deltclass";
    case RTM_NEWTFILTER: return "newtfilter";
    case RTM_DELTFILTER: return "deltfilter";
    default: return "unknown";
    }
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

void handle_rtnetlink_notification(struct netif *nb, int bytecount)
{
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

    if (mnl_cb_run(nb->nlbuf, bytecount, 0, 0, netif_encode_rtnetlink, &state) <= 0)
        err(EXIT_FAILURE, "mnl_cb_run");

    nb->resp[nb->resp_index++] = ERL_NIL_EXT; // One would think there's be an ei_encode_nil..
    ei_encode_list_header(nb->resp, &list_index, state.count[0]);

    erlcmd_send(nb->resp, nb->resp_index);
}
