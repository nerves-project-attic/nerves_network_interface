/*
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

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "erlcmd.h"

//#define DEBUG
#ifdef DEBUG
#define debug(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\r\n"); } while(0)
#else
#define debug(...)
#endif

struct net_basic {
    // Netlink socket information
    struct mnl_socket *nl;
    int seq;

    // AF_INET socket for ioctls
    int inet_fd;

    // Netlink buffering
    char nlbuf[8192]; // See MNL_SOCKET_BUFFER_SIZE

    // Erlang request processing
    const char *req;
    int req_index;

    // Erlang response processing
    char resp[ERLCMD_BUF_SIZE];
    int resp_index;

    // Holder of the most recently encounted error message if there is one.
    const char *last_error;
};

static void net_basic_init(struct net_basic *nb)
{
    memset(nb, 0, sizeof(*nb));
    nb->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nb->nl)
        errx(EXIT_FAILURE, "mnl_socket_open");

    if (mnl_socket_bind(nb->nl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
        errx(EXIT_FAILURE, "mnl_socket_bind");

    nb->inet_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nb->inet_fd < 0)
        err(EXIT_FAILURE, "socket");

    nb->seq = 1;
}

static void net_basic_cleanup(struct net_basic *nb)
{
    mnl_socket_close(nb->nl);
    nb->nl = NULL;
}

static int collect_if_attrs(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // Skip unsupported attributes in user-space
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
        return MNL_CB_OK;

    // Only save supported attributes (see encode logic)
    switch (type) {
    case IFLA_MTU:
    case IFLA_IFNAME:
    case IFLA_ADDRESS:
    case IFLA_BROADCAST:
    case IFLA_LINK:
    case IFLA_OPERSTATE:
    case IFLA_STATS:
        tb[type] = attr;
        break;

    default:
        break;
    }
    return MNL_CB_OK;
}

static void encode_kv_long(struct net_basic *nb, const char *key, long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_long(nb->resp, &nb->resp_index, value);
}

static void encode_kv_ulong(struct net_basic *nb, const char *key, unsigned long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_ulong(nb->resp, &nb->resp_index, value);
}
static void encode_kv_bool(struct net_basic *nb, const char *key, int value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_boolean(nb->resp, &nb->resp_index, value);
}
static void encode_string(char *buf, int *index, const char *str)
{
    // Encode strings as binaries so that we get Elixir strings
    // NOTE: the strings that we encounter here are expected to be ASCII to
    //       my knowledge
    ei_encode_binary(buf, index, str, strlen(str));
}
static void encode_kv_string(struct net_basic *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    encode_string(nb->resp, &nb->resp_index, str);
}

static void encode_kv_stats(struct net_basic *nb, const char *key, struct nlattr *attr)
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

static int net_basic_build_ifinfo(const struct nlmsghdr *nlh, void *data)
{
    struct net_basic *nb = (struct net_basic *) data;
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    if (mnl_attr_parse(nlh, sizeof(*ifm), collect_if_attrs, tb) != MNL_CB_OK) {
        debug("Error from mnl_attr_parse");
        return MNL_CB_ERROR;
    }

    int count = 7; // Number of fields that we always encode
    int i;
    for (i = 0; i <= IFLA_MAX; i++)
        if (tb[i])
            count++;

    ei_encode_map_header(nb->resp, &nb->resp_index, count);

    encode_kv_long(nb, "index", ifm->ifi_index);

    ei_encode_atom(nb->resp, &nb->resp_index, "type");
    ei_encode_atom(nb->resp, &nb->resp_index, ifm->ifi_type == ARPHRD_ETHER ? "ethernet" : "other");

    encode_kv_bool(nb, "is_up", ifm->ifi_flags & IFF_UP);
    encode_kv_bool(nb, "is_broadcast", ifm->ifi_flags & IFF_BROADCAST);
    encode_kv_bool(nb, "is_running", ifm->ifi_flags & IFF_RUNNING);
    encode_kv_bool(nb, "is_lower_up", ifm->ifi_flags & IFF_LOWER_UP);
    encode_kv_bool(nb, "is_multicast", ifm->ifi_flags & IFF_MULTICAST);

    if (tb[IFLA_MTU])
        encode_kv_ulong(nb, "mtu", mnl_attr_get_u32(tb[IFLA_MTU]));
    if (tb[IFLA_IFNAME])
        encode_kv_string(nb, "ifname", mnl_attr_get_str(tb[IFLA_IFNAME]));
    if (tb[IFLA_ADDRESS]) {
        ei_encode_atom(nb->resp, &nb->resp_index, "mac_address");
        ei_encode_binary(nb->resp, &nb->resp_index, mnl_attr_get_payload(tb[IFLA_ADDRESS]), mnl_attr_get_payload_len(tb[IFLA_ADDRESS]));
    }
    if (tb[IFLA_BROADCAST]) {
        ei_encode_atom(nb->resp, &nb->resp_index, "mac_broadcast");
        ei_encode_binary(nb->resp, &nb->resp_index, mnl_attr_get_payload(tb[IFLA_BROADCAST]), mnl_attr_get_payload_len(tb[IFLA_BROADCAST]));
    }
    if (tb[IFLA_LINK])
        encode_kv_ulong(nb, "link", mnl_attr_get_u32(tb[IFLA_LINK]));
    if (tb[IFLA_OPERSTATE])
        encode_kv_string(nb, "operstate", mnl_attr_get_str(tb[IFLA_OPERSTATE]));
    if (tb[IFLA_STATS])
        encode_kv_stats(nb, "stats", tb[IFLA_STATS]);

    return MNL_CB_OK;
}

static void net_basic_process(struct net_basic *nb)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];

    int bytecount = mnl_socket_recvfrom(nb->nl, buf, sizeof(buf));
    if (bytecount <= 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    // Create the notification
    nb->resp_index = sizeof(uint16_t); // Skip over payload size
    nb->resp[nb->resp_index++] = 'n';
    ei_encode_version(nb->resp, &nb->resp_index);

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);

    // Currently, the only notifications are interface changes.
    ei_encode_atom(nb->resp, &nb->resp_index, "ifchanged");
    if (mnl_cb_run(buf, bytecount, 0, 0, net_basic_build_ifinfo, nb) <= 0)
        errx(EXIT_FAILURE, "mnl_cb_run");

    erlcmd_send(nb->resp, nb->resp_index);
}

static void net_basic_handle_interfaces(struct net_basic *nb)
{
    struct if_nameindex *if_ni = if_nameindex();
    if (if_ni == NULL)
        err(EXIT_FAILURE, "if_nameindex");

    for (struct if_nameindex *i = if_ni;
         ! (i->if_index == 0 && i->if_name == NULL);
         i++) {
        debug("Found interface %s.", i->if_name);
        ei_encode_list_header(nb->resp, &nb->resp_index, 1);
        encode_string(nb->resp, &nb->resp_index, i->if_name);
    }

    if_freenameindex(if_ni);

    ei_encode_empty_list(nb->resp, &nb->resp_index);
}

static void net_basic_handle_status(struct net_basic *nb,
                                    const char *ifname)
{
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;
    unsigned int seq;

    nlh = mnl_nlmsg_put_header(nb->nlbuf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = seq = nb->seq++;

    ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = ARPHRD_ETHER;
    ifi->ifi_index = 0;
    ifi->ifi_flags = 0;
    ifi->ifi_change = 0xffffffff;

    mnl_attr_put_str(nlh, IFLA_IFNAME, ifname);

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0)
        err(EXIT_FAILURE, "mnl_socket_send");

    unsigned int portid = mnl_socket_get_portid(nb->nl);

    int original_resp_index = nb->resp_index;
    ssize_t ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    if (ret < 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    if (mnl_cb_run(nb->nlbuf, ret, seq, portid, net_basic_build_ifinfo, nb) < 0) {
        debug("error from or mnl_cb_run?");
        nb->resp_index = original_resp_index;
        ei_encode_atom(nb->resp, &nb->resp_index, "error");
    }
}

static void net_basic_set_ifflags(struct net_basic *nb,
                                  const char *ifname,
                                  uint32_t flags,
                                  uint32_t mask)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(nb->inet_fd, SIOCGIFFLAGS, &ifr) < 0) {
        debug("SIOCGIFFLAGS error: %s", strerror(errno));
        ei_encode_atom(nb->resp, &nb->resp_index, "error");
        return;
    }

    if ((ifr.ifr_flags ^ flags) & mask) {
        ifr.ifr_flags = (ifr.ifr_flags & ~mask) | (mask & flags);
        if (ioctl(nb->inet_fd, SIOCSIFFLAGS, &ifr)) {
            debug("SIOCGIFFLAGS error: %s", strerror(errno));
            ei_encode_atom(nb->resp, &nb->resp_index, "error");
            return;
        }
    }
    erlcmd_encode_ok(nb->resp, &nb->resp_index);
}

static int collect_route_attrs(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // Skip unsupported attributes in user-space
    if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
        return MNL_CB_OK;

    tb[type] = attr;
    return MNL_CB_OK;
}

struct fdg_data {
    int oif;
    char *result;
};

static int check_default_gateway(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[RTA_MAX + 1] = {};
    struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
    mnl_attr_parse(nlh, sizeof(*rm), collect_route_attrs, tb);

    struct fdg_data *fdg = (struct fdg_data *) data;
    if (rm->rtm_scope == 0 &&
            tb[RTA_OIF] &&
            (int) mnl_attr_get_u32(tb[RTA_OIF]) == fdg->oif &&
            tb[RTA_GATEWAY]) {
        // Found it.
        inet_ntop(AF_INET, mnl_attr_get_payload(tb[RTA_GATEWAY]), fdg->result, INET_ADDRSTRLEN);
    }

    return MNL_CB_OK;
}

static void find_default_gateway(struct net_basic *nb,
                                int oif,
                                char *result)
{
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    unsigned int seq;

    nlh = mnl_nlmsg_put_header(nb->nlbuf);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = nb->seq++;

    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = AF_INET;

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0)
        err(EXIT_FAILURE, "mnl_socket_send");

    unsigned int portid = mnl_socket_get_portid(nb->nl);

    struct fdg_data fdg;
    fdg.oif = oif;
    fdg.result = result;
    *fdg.result = '\0';

    ssize_t ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    while (ret > 0) {
        ret = mnl_cb_run(nb->nlbuf, ret, seq, portid, check_default_gateway, &fdg);
        if (ret <= MNL_CB_STOP)
            break;
        ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    }
    if (ret == -1)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");
}

struct ip_setting_handler {
    const char *name;
    int (*set)(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);
    int (*get)(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);

    // data for handlers
    int ioctl_set;
    int ioctl_get;
};

static int set_ipaddr_ioctl(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);
static int get_ipaddr_ioctl(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);
static int set_default_gateway(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);
static int get_default_gateway(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname);

static struct ip_setting_handler handlers[] = {
    { "ipv4_address", set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFADDR, SIOCGIFADDR },
    { "ipv4_broadcast", set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFBRDADDR, SIOCGIFBRDADDR },
    { "ipv4_subnet_mask", set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFNETMASK, SIOCGIFNETMASK },
    { "ipv4_gateway", set_default_gateway, get_default_gateway, 0, 0 },
    { NULL, NULL, NULL, 0, 0 }
};

#define HANDLER_COUNT ((sizeof(handlers) / sizeof(handlers[0])) - 1)

static int set_ipaddr_ioctl(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    char ipaddr[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    // Be forgiving and if the user specifies an empty IP address, just skip
    // this request.
    if (ipaddr[0] == '\0')
        return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, ipaddr, &addr->sin_addr) <= 0) {
        debug("Bad IP address for '%s': %s", handler->name, ipaddr);
        nb->last_error = "bad_ip_address";
        return -1;
    }

    if (ioctl(nb->inet_fd, handler->ioctl_set, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = strerror(errno); // Think about this
        return -1;
    }

    return 0;
}

static int get_ipaddr_ioctl(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, handler->ioctl_get, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for getting '%s': %s", handler->ioctl_get, handler->name, strerror(errno));
        nb->last_error = strerror(errno); // Think about this
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (addr->sin_family == AF_INET) {
        char addrstr[INET_ADDRSTRLEN];
        if (!inet_ntop(addr->sin_family, &addr->sin_addr, addrstr, sizeof(addrstr))) {
            debug("inet_ntop failed for '%s'? : %s", handler->name, strerror(errno));
            nb->last_error = strerror(errno); // Think about this
            return -1;
        }
        encode_kv_string(nb, handler->name, addrstr);
    } else {
        debug("got unexpected sin_family %d for '%s'", addr->sin_family, handler->name);
        nb->last_error = "bad family";
        return -1;
    }
    return 0;
}

static int remove_all_gateways(struct net_basic *nb, const char *ifname)
{
    struct rtentry route;
    memset(&route, 0, sizeof(route));

    struct sockaddr_in *addr = (struct sockaddr_in *) &route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in*) &route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in*) &route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_dev = (char *) ifname;
    route.rt_flags = RTF_GATEWAY;
    route.rt_metric = 0;

    // There may be more than one gateway. Remove all
    // of them.
    for (;;) {
        int rc = ioctl(nb->inet_fd, SIOCDELRT, &route);
        if (rc < 0) {
            if (errno == ESRCH) {
                return 0;
            } else {
                nb->last_error = strerror(errno);
                return -1;
            }
        }
    }
}

static int add_default_gateway(struct net_basic *nb, const char *ifname, const char *gateway_ip)
{
    struct rtentry route;
    memset(&route, 0, sizeof(route));

    struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, gateway_ip, &addr->sin_addr) <= 0) {
        debug("Bad IP address for the default gateway: %s", gateway_ip);
        nb->last_error = "bad_ip_address";
        return -1;
    }

    addr = (struct sockaddr_in*) &route.rt_dst;
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in*) &route.rt_genmask;
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_dev = (char *) ifname;
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;

    int rc = ioctl(nb->inet_fd, SIOCADDRT, &route);
    if (rc < 0 && errno != EEXIST) {
        nb->last_error = strerror(errno);
        return -1;
    }
    return 0;
}

static int set_default_gateway(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname)
{
    char gateway[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, gateway, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    // Before one can be set, any configured gateways need to be removed.
    if (remove_all_gateways(nb, ifname) < 0)
        return -1;

    return add_default_gateway(nb, ifname, gateway);
}

static int ifname_to_index(struct net_basic *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, SIOCGIFINDEX, &ifr) < 0) {
        nb->last_error = strerror(errno);
        return -1;
    }
    return ifr.ifr_ifindex;
}

static int get_default_gateway(struct ip_setting_handler *handler, struct net_basic *nb, const char *ifname)
{
    int oif = ifname_to_index(nb, ifname);
    if (oif < 0)
        return -1;

    char gateway_ip[INET_ADDRSTRLEN];
    find_default_gateway(nb, oif, gateway_ip);

    // If the gateway isn't found, then the empty string is what we want.
    encode_kv_string(nb, handler->name, gateway_ip);
    return 0;
}

static void net_basic_handle_get(struct net_basic *nb,
                                 const char *ifname)
{
    int original_resp_index = nb->resp_index;

    ei_encode_map_header(nb->resp, &nb->resp_index, HANDLER_COUNT);

    nb->last_error = NULL;
    struct ip_setting_handler *handler = handlers;
    while (handler->name &&
           handler->get(handler, nb, ifname) >= 0)
        handler++;

    if (nb->last_error) {
        nb->resp_index = original_resp_index;
        erlcmd_encode_error_tuple(nb->resp, &nb->resp_index, nb->last_error);
    }
}

static struct ip_setting_handler *find_handler(const char *name)
{
    struct ip_setting_handler *handler = handlers;
    while (handler->name) {
        if (strcmp(handler->name, name) == 0)
            return handler;
        handler++;
    }
    return NULL;
}

static void net_basic_handle_set(struct net_basic *nb,
                                 const char *ifname)
{
    nb->last_error = NULL;

    int arity;
    if (ei_decode_map_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "setting attributes requires a map");

    int i;
    for (i = 0; i < arity && nb->last_error == NULL; i++) {
        char name[32];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, name, sizeof(name)) < 0)
            errx(EXIT_FAILURE, "error in map encoding");

        // Look up the option. If we don't know it, silently ignore it so that
        // the caller can pass in maps that contain options for other code.
        struct ip_setting_handler *handler = find_handler(name);
        if (handler)
            handler->set(handler, nb, ifname);
        else
            ei_skip_term(nb->req, &nb->req_index);
    }
    if (nb->last_error)
        erlcmd_encode_error_tuple(nb->resp, &nb->resp_index, nb->last_error);
    else
        erlcmd_encode_ok(nb->resp, &nb->resp_index);
}

static void net_basic_request_handler(const char *req, void *cookie)
{
    struct net_basic *nb = (struct net_basic *) cookie;
    char ifname[IFNAMSIZ];

    // Commands are of the form {Command, Arguments}:
    // { atom(), term() }
    nb->req_index = sizeof(uint16_t);
    nb->req = req;
    if (ei_decode_version(nb->req, &nb->req_index, NULL) < 0)
        errx(EXIT_FAILURE, "Message version issue?");

    int arity;
    if (ei_decode_tuple_header(nb->req, &nb->req_index, &arity) < 0 ||
            arity != 2)
        errx(EXIT_FAILURE, "expecting {cmd, args} tuple");

    char cmd[MAXATOMLEN];
    if (ei_decode_atom(nb->req, &nb->req_index, cmd) < 0)
        errx(EXIT_FAILURE, "expecting command atom");

    nb->resp_index = sizeof(uint16_t); // Space for payload size
    nb->resp[nb->resp_index++] = 'r'; // Indicate response
    ei_encode_version(nb->resp, &nb->resp_index);
    if (strcmp(cmd, "interfaces") == 0) {
        debug("interfaces");
        net_basic_handle_interfaces(nb);
    } else if (strcmp(cmd, "status") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "status requires ifname");
        debug("ifinfo: %s", ifname);
        net_basic_handle_status(nb, ifname);
    } else if (strcmp(cmd, "ifup") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "ifup requires ifname");
        debug("ifup: %s", ifname);
        net_basic_set_ifflags(nb, ifname, IFF_UP, IFF_UP);
    } else if (strcmp(cmd, "ifdown") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "ifdown requires ifname");
        debug("ifdown: %s", ifname);
        net_basic_set_ifflags(nb, ifname, 0, IFF_UP);
    } else if (strcmp(cmd, "set_config") == 0) {
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &arity) < 0 ||
                arity != 2 ||
                erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "set_config requires {ifname, parameters}");
        debug("set: %s", ifname);
        net_basic_handle_set(nb, ifname);
    } else if (strcmp(cmd, "get_config") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "get_config requires ifname");
        debug("get: %s", ifname);
        net_basic_handle_get(nb, ifname);
    } else
        errx(EXIT_FAILURE, "unknown command: %s", cmd);

    debug("sending response: %d bytes", nb->resp_index);
    erlcmd_send(nb->resp, nb->resp_index);
}

int main(int argc, char *argv[])
{
    struct net_basic nb;
    net_basic_init(&nb);

    struct erlcmd handler;
    erlcmd_init(&handler, net_basic_request_handler, &nb);

    for (;;) {
        struct pollfd fdset[2];

        fdset[0].fd = STDIN_FILENO;
        fdset[0].events = POLLIN;
        fdset[0].revents = 0;

        fdset[1].fd = mnl_socket_get_fd(nb.nl);
        fdset[1].events = POLLIN;
        fdset[1].revents = 0;

        int rc = poll(fdset, 2, -1);
        if (rc < 0) {
            // Retry if EINTR
            if (errno == EINTR)
                continue;

            err(EXIT_FAILURE, "poll");
        }

        if (fdset[0].revents & (POLLIN | POLLHUP))
            erlcmd_process(&handler);
        if (fdset[1].revents & (POLLIN | POLLHUP))
            net_basic_process(&nb);
    }

    net_basic_cleanup(&nb);
    return 0;
}
