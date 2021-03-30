/*
 *  Copyright 2014-2017 Frank Hunleth
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

/****************************************************************
 * Copyright (C) 2021 Schneider Electric                        *
 ****************************************************************/


#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ipv6.h>
#include <netinet/in.h>

// In Ubuntu 16.04, it seems that the new compat logic handling is preventing
// IFF_LOWER_UP from being defined properly. It looks like a bug, so define it
// here so that this file compiles.  A scan of all Nerves platforms and Ubuntu
// 16.04 has IFF_LOWER_UP always being set to 0x10000. this being defined as
// 0x10000.
#define WORKAROUND_IFF_LOWER_UP (0x10000)

#define MACADDR_STR_LEN      18 // aa:bb:cc:dd:ee:ff and a null terminator
#define MAX_PREFIX_LEN       5  // length of "/128" (4-bytes) + length of '\0' termination string

#include "erlcmd.h"

#include "debug.h"

struct netif {
    // NETLINK_ROUTE socket information
    struct mnl_socket *nl;
    int seq;

    // NETLINK_KOBJECT_UEVENT socket information
    struct mnl_socket *nl_uevent;

    // AF_INET socket for ioctls
    int inet_fd;

    // AF_INET6 socket for ioctls
    int inet6_fd;

    // Netlink buffering
    char nlbuf[8192]; // See MNL_SOCKET_BUFFER_SIZE

    // Erlang request processing
    const char *req;
    int req_index;

    // Erlang response processing
    char resp[ERLCMD_BUF_SIZE];
    int resp_index;

    // Async response handling
    void (*response_callback)(struct netif *nb, int bytecount);
    void (*response_error_callback)(struct netif *nb, int err);
    unsigned int response_portid;
    int response_seq;

    // Holder of the most recently encounted errno.
    int last_error;
};

static void netif_init(struct netif *nb)
{
    memset(nb, 0, sizeof(*nb));
    nb->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nb->nl)
        err(EXIT_FAILURE, "mnl_socket_open (NETLINK_ROUTE)");

    if (mnl_socket_bind(nb->nl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
        err(EXIT_FAILURE, "mnl_socket_bind");

    nb->nl_uevent = mnl_socket_open(NETLINK_KOBJECT_UEVENT);
    if (!nb->nl_uevent)
        err(EXIT_FAILURE, "mnl_socket_open (NETLINK_KOBJECT_UEVENT)");

    // There is one single group in kobject over netlink
    if (mnl_socket_bind(nb->nl_uevent, (1<<0), MNL_SOCKET_AUTOPID) < 0)
        err(EXIT_FAILURE, "mnl_socket_bind");

    nb->inet_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nb->inet_fd < 0)
        err(EXIT_FAILURE, "socket");

    nb->inet6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (nb->inet6_fd < 0)
        err(EXIT_FAILURE, "socket6");

    nb->seq = 1;
}

static void netif_cleanup(struct netif *nb)
{
    mnl_socket_close(nb->nl);
    mnl_socket_close(nb->nl_uevent);
    nb->nl = NULL;
}

static void start_response(struct netif *nb)
{
    nb->resp_index = sizeof(uint16_t); // Space for payload size
    nb->resp[nb->resp_index++] = 'r'; // Indicate response
    ei_encode_version(nb->resp, &nb->resp_index);
}

static void send_response(struct netif *nb)
{
    debug("sending response: %d bytes", nb->resp_index);
    erlcmd_send(nb->resp, nb->resp_index);
    nb->resp_index = 0;
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


static int string_to_macaddr(const char *str, unsigned char *mac)
{
    if (sscanf(str,
               "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &mac[0], &mac[1], &mac[2],
               &mac[3], &mac[4], &mac[5]) != 6)
        return -1;
    else
        return 0;
}
static int macaddr_to_string(const unsigned char *mac, char *str)
{
    snprintf(str, MACADDR_STR_LEN,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
    return 0;
}

static void encode_kv_long(struct netif *nb, const char *key, long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_long(nb->resp, &nb->resp_index, value);
}

static void encode_kv_ulong(struct netif *nb, const char *key, unsigned long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_ulong(nb->resp, &nb->resp_index, value);
}
static void encode_kv_bool(struct netif *nb, const char *key, int value)
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
static void encode_kv_string(struct netif *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    encode_string(nb->resp, &nb->resp_index, str);
}
static void encode_kv_atom(struct netif *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_atom(nb->resp, &nb->resp_index, str);
}

static void encode_kv_macaddr(struct netif *nb, const char *key, const unsigned char *macaddr)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);

    char macaddr_str[MACADDR_STR_LEN];

    // Only handle 6 byte mac addresses (to my knowledge, this is the only case)
    macaddr_to_string(macaddr, macaddr_str);

    encode_string(nb->resp, &nb->resp_index, macaddr_str);
}

static void encode_kv_stats(struct netif *nb, const char *key, struct nlattr *attr)
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

static int netif_build_ifinfo(const struct nlmsghdr *nlh, void *data)
{
    struct netif *nb = (struct netif *) data;
    struct nlattr *tb[IFLA_MAX + 1];
    memset(tb, 0, sizeof(tb));
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    if (mnl_attr_parse(nlh, sizeof(*ifm), collect_if_attrs, tb) != MNL_CB_OK) {
        debugf("Error from mnl_attr_parse");
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
    encode_kv_bool(nb, "is_lower_up", ifm->ifi_flags & WORKAROUND_IFF_LOWER_UP);
    encode_kv_bool(nb, "is_multicast", ifm->ifi_flags & IFF_MULTICAST);
    encode_kv_bool(nb, "is_all-multicast", ifm->ifi_flags & IFF_ALLMULTI);

    if (tb[IFLA_MTU])
        encode_kv_ulong(nb, "mtu", mnl_attr_get_u32(tb[IFLA_MTU]));
    if (tb[IFLA_IFNAME])
        encode_kv_string(nb, "ifname", mnl_attr_get_str(tb[IFLA_IFNAME]));
    if (tb[IFLA_ADDRESS])
        encode_kv_macaddr(nb, "mac_address", mnl_attr_get_payload(tb[IFLA_ADDRESS]));
    if (tb[IFLA_BROADCAST])
        encode_kv_macaddr(nb, "mac_broadcast", mnl_attr_get_payload(tb[IFLA_BROADCAST]));
    if (tb[IFLA_LINK])
        encode_kv_ulong(nb, "link", mnl_attr_get_u32(tb[IFLA_LINK]));
    if (tb[IFLA_OPERSTATE])
        encode_kv_operstate(nb, mnl_attr_get_u32(tb[IFLA_OPERSTATE]));
    if (tb[IFLA_STATS])
        encode_kv_stats(nb, "stats", tb[IFLA_STATS]);

    return MNL_CB_OK;
}

static void nl_uevent_process(struct netif *nb)
{
    int bytecount = mnl_socket_recvfrom(nb->nl_uevent, nb->nlbuf, sizeof(nb->nlbuf));
    if (bytecount <= 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    // uevent messages are concatenated strings
    enum hotplug_operation {
        HOTPLUG_OPERATION_NONE = 0,
        HOTPLUG_OPERATION_ADD,
        HOTPLUG_OPERATION_MOVE,
        HOTPLUG_OPERATION_REMOVE
    } operation = HOTPLUG_OPERATION_NONE;

    const char *str = nb->nlbuf;
    if (strncmp(str, "add@", 4) == 0)
        operation = HOTPLUG_OPERATION_ADD;
    else if (strncmp(str, "move@", 5) == 0)
        operation = HOTPLUG_OPERATION_MOVE;
    else if (strncmp(str, "remove@", 7) == 0)
        operation = HOTPLUG_OPERATION_REMOVE;
    else
        return; // Not interested in this message.

    const char *str_end = str + bytecount;
    str += strlen(str) + 1;

    // Extract the fields of interest
    const char *ifname = NULL;
    const char *subsystem = NULL;
    const char *ifindex = NULL;
    for (;str < str_end; str += strlen(str) + 1) {
        if (strncmp(str, "INTERFACE=", 10) == 0)
            ifname = str + 10;
        else if (strncmp(str, "SUBSYSTEM=", 10) == 0)
            subsystem = str + 10;
        else if (strncmp(str, "IFINDEX=", 8) == 0)
            ifindex = str + 8;
    }

    // Check that we have the required fields that this is a
    // "net" subsystem event. If yes, send the notification.
    if (ifname && subsystem && ifindex && strcmp(subsystem, "net") == 0) {
        nb->resp_index = sizeof(uint16_t); // Skip over payload size
        nb->resp[nb->resp_index++] = 'n';
        ei_encode_version(nb->resp, &nb->resp_index);

        ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);

        switch (operation) {
        case HOTPLUG_OPERATION_ADD:
            ei_encode_atom(nb->resp, &nb->resp_index, "ifadded");
            break;
        case HOTPLUG_OPERATION_MOVE:
            ei_encode_atom(nb->resp, &nb->resp_index, "ifrenamed");
            break;
        case HOTPLUG_OPERATION_REMOVE:
        default: // Silence warning
            ei_encode_atom(nb->resp, &nb->resp_index, "ifremoved");
            break;
        }

        ei_encode_map_header(nb->resp, &nb->resp_index, 2);

        encode_kv_long(nb, "index", strtol(ifindex, NULL, 0));
        encode_kv_string(nb, "ifname", ifname);

        erlcmd_send(nb->resp, nb->resp_index);
    }
}

static void handle_notification(struct netif *nb, int bytecount)
{
    debug("[%s %d %s]: bytecount = %d\r\n", __FILE__, __LINE__, __FUNCTION__, bytecount);

    // Create the notification
    nb->resp_index = sizeof(uint16_t); // Skip over payload size
    nb->resp[nb->resp_index++] = 'n';
    ei_encode_version(nb->resp, &nb->resp_index);

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);

    // Currently, the only notifications are interface changes.
    ei_encode_atom(nb->resp, &nb->resp_index, "ifchanged");
    if (mnl_cb_run(nb->nlbuf, bytecount, 0, 0, netif_build_ifinfo, nb) <= 0)
        err(EXIT_FAILURE, "mnl_cb_run");

    erlcmd_send(nb->resp, nb->resp_index);
}

static void handle_async_response(struct netif *nb, int bytecount)
{
    debug("[%s %d %s]: bytecount = %d\r\n", __FILE__, __LINE__, __FUNCTION__, bytecount);

    nb->response_callback(nb, bytecount);
    nb->response_callback = NULL;
    nb->response_error_callback = NULL;
}

static void handle_async_response_error(struct netif *nb, int err)
{
    debug("[%s %d %s]: err = %d\r\n", __FILE__, __LINE__, __FUNCTION__, err);

    nb->response_error_callback(nb, err);
    nb->response_callback = NULL;
    nb->response_error_callback = NULL;
}

static void nl_route_process(struct netif *nb)
{
    int bytecount = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));

    debug("[%s %d %s]: bytecount = %d\r\n", __FILE__, __LINE__, __FUNCTION__, bytecount);

    if (bytecount <= 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    // Check if there's an async response on the saved sequence number and port id.
    // If not or if the message is not expected, then it's a notification.
    if (nb->response_callback != NULL) {
        int rc = mnl_cb_run(nb->nlbuf, bytecount, nb->response_seq, nb->response_portid, NULL, NULL);
        if (rc == MNL_CB_OK)
            handle_async_response(nb, bytecount);
        else if (rc == MNL_CB_ERROR && errno != ESRCH && errno != EPROTO)
            handle_async_response_error(nb, errno);
        else
            handle_notification(nb, bytecount);
    } else
        handle_notification(nb, bytecount);
}

static void netif_handle_interfaces(struct netif *nb)
{
    struct if_nameindex *if_ni = if_nameindex();
    if (if_ni == NULL)
        err(EXIT_FAILURE, "if_nameindex");

    start_response(nb);
    for (struct if_nameindex *i = if_ni;
         ! (i->if_index == 0 && i->if_name == NULL);
         i++) {
        debug("Found interface %s.", i->if_name);
        ei_encode_list_header(nb->resp, &nb->resp_index, 1);
        encode_string(nb->resp, &nb->resp_index, i->if_name);
    }

    if_freenameindex(if_ni);

    ei_encode_empty_list(nb->resp, &nb->resp_index);
    send_response(nb);
}

static void netif_handle_status_callback(struct netif *nb, int bytecount)
{
    debug("[%s %d %s]: bytecount = %d\r\n", __FILE__, __LINE__, __FUNCTION__, bytecount);

    start_response(nb);

    int original_resp_index = nb->resp_index;

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);
    ei_encode_atom(nb->resp, &nb->resp_index, "ok");
    if (mnl_cb_run(nb->nlbuf, bytecount, nb->response_seq, nb->response_portid, netif_build_ifinfo, nb) < 0) {
        debugf("error from or mnl_cb_run?");
        nb->resp_index = original_resp_index;
        erlcmd_encode_errno_error(nb->resp, &nb->resp_index, errno);
    }

    send_response(nb);
}

static void netif_handle_status_error_callback(struct netif *nb, int err)
{
    debug("[%s %d %s]: err = %d\r\n", __FILE__, __LINE__, __FUNCTION__, err);

    start_response(nb);
    erlcmd_encode_errno_error(nb->resp, &nb->resp_index, err);
    send_response(nb);
}

static void netif_handle_status(struct netif *nb,
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

    nb->response_callback = netif_handle_status_callback;
    nb->response_error_callback = netif_handle_status_error_callback;
    nb->response_portid = mnl_socket_get_portid(nb->nl);
    nb->response_seq = seq;
}

static void netif_set_ifflags(struct netif *nb,
                                  const char *ifname,
                                  uint32_t flags,
                                  uint32_t mask)
{
    struct ifreq ifr;

    start_response(nb);

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(nb->inet_fd, SIOCGIFFLAGS, &ifr) < 0) {
        debug("SIOCGIFFLAGS error: %s", strerror(errno));
        erlcmd_encode_errno_error(nb->resp, &nb->resp_index, errno);
        send_response(nb);
        return;
    }

    if ((ifr.ifr_flags ^ flags) & mask) {
        ifr.ifr_flags = (ifr.ifr_flags & ~mask) | (mask & flags);
        if (ioctl(nb->inet_fd, SIOCSIFFLAGS, &ifr)) {
            debug("SIOCGIFFLAGS error: %s", strerror(errno));
            erlcmd_encode_errno_error(nb->resp, &nb->resp_index, errno);
            send_response(nb);
            return;
        }
    }
    erlcmd_encode_ok(nb->resp, &nb->resp_index);
    send_response(nb);
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
    struct nlattr *tb[RTA_MAX + 1];
    memset(tb, 0, sizeof(tb));
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

static int check_default_gateway6(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[RTA_MAX + 1];
    memset(tb, 0, sizeof(tb));
    struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
    mnl_attr_parse(nlh, sizeof(*rm), collect_route_attrs, tb);

    struct fdg_data *fdg = (struct fdg_data *) data;
    if (rm->rtm_scope == 0 &&
            tb[RTA_OIF] &&
            (int) mnl_attr_get_u32(tb[RTA_OIF]) == fdg->oif &&
            tb[RTA_GATEWAY]) {
        // Found it.
        inet_ntop(AF_INET6, mnl_attr_get_payload(tb[RTA_GATEWAY]), fdg->result, INET6_ADDRSTRLEN);
    }

    return MNL_CB_OK;
}

static void find_default_gateway(struct netif *nb,
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

static void find_default_gateway6(struct netif *nb,
                                int oif,
                                char *result)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(nb->nlbuf);
    struct rtmsg *rtm    = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    unsigned int portid = 0;
    unsigned int seq    = 0;
    ssize_t ret         = 0;
    struct fdg_data fdg = { .oif = oif, .result = result };

    nlh->nlmsg_type  = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq   = seq = nb->seq++;

    rtm->rtm_family = AF_INET6;

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0)
        err(EXIT_FAILURE, "mnl_socket_send");

    mnl_socket_get_portid(nb->nl);

    fdg.result[0] = '\0';

    ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    while (ret > 0) {
        ret = mnl_cb_run(nb->nlbuf, ret, seq, portid, check_default_gateway6, &fdg);
        if (ret <= MNL_CB_STOP)
            break;
        ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    }
    if (ret == -1)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");
}

struct ip_setting_handler {
    const char *name;
    int (*prep)(const struct ip_setting_handler *handler, struct netif *nb, void **context);
    int (*set)(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
    int (*get)(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);

    // data for handlers
    int ioctl_set;
    int ioctl_get;
};

static int prep_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int prep_ipaddr(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int remove_ipaddr(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int set_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipaddr6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int remove_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int prep_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int prep_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int ifname_to_index(struct netif *nb, const char *ifname);
static int add_default_gateway6(struct netif *nb, const char *ifname, const char *gateway_ip, const unsigned short flags);
static int remove_gateway6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int remove_gateway6(struct netif *nb, const char *ifname, const struct in6_addr *gw_addr, const unsigned short flags);
static int prep_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);


/* These handlers are listed in the order that they should be invoked when
 * configuring the interface. For example, "ipv4_gateway" is listed at the end
 * so that it is set after the address and subnet_mask. If this is not done,
 * setting the gateway may fail since Linux thinks that it is on the wrong subnet.
 */
static const struct ip_setting_handler handlers[] = {
  { .name = "ipv4_address",
    .prep = prep_ipaddr_ioctl,
    .set  = set_ipaddr_ioctl,
    .get  = get_ipaddr_ioctl,
    .ioctl_set = SIOCSIFADDR,
    .ioctl_get = SIOCGIFADDR,
  },
  { .name = "-ipv4_address",
    .prep = prep_ipaddr,
    .set  = remove_ipaddr,
    .get  = NULL,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv4_subnet_mask",
    .prep = prep_ipaddr_ioctl,
    .set  = set_ipaddr_ioctl,
    .get  = get_ipaddr_ioctl,
    .ioctl_set = SIOCSIFNETMASK,
    .ioctl_get = SIOCGIFNETMASK,
  },
  { .name = "ipv4_broadcast",
    .prep = prep_ipaddr_ioctl,
    .set  = set_ipaddr_ioctl,
    .get  = get_ipaddr_ioctl,
    .ioctl_set  = SIOCSIFBRDADDR,
    .ioctl_get  = SIOCGIFBRDADDR,
  },
  { .name = "ipv6_address",
    .prep = prep_ipaddr6_ioctl,
    .set  = set_ipaddr6_ioctl,
    .get  = get_ipaddr6,
    .ioctl_set = SIOCSIFADDR,
    .ioctl_get = 0,
  },
  { .name = "ipv4_gateway",
    .prep = prep_default_gateway,
    .set  = set_default_gateway,
    .get  = get_default_gateway,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv6_gateway",
    .prep = prep_default_gateway6,
    .set  = set_default_gateway6,
    .get  = get_default_gateway6,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "mac_address",
    .prep = prep_mac_address_ioctl,
    .set  = set_mac_address_ioctl,
    .get  = get_mac_address_ioctl,
    .ioctl_set = SIOCSIFHWADDR,
    .ioctl_get = SIOCGIFHWADDR,
  },
  { .name = "ipv6_autoconf",
    .prep = prep_ipv6_autoconf,
    .set  = set_ipv6_autoconf,
    .get  = get_ipv6_autoconf,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv6_disable",
    .prep = prep_ipv6_disable,
    .set  = set_ipv6_disable,
    .get  = get_ipv6_disable,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv6_accept_ra",
    .prep = prep_ipv6_accept_ra,
    .set  = set_ipv6_accept_ra,
    .get  = get_ipv6_accept_ra,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv6_accept_ra_pinfo",
    .prep = prep_ipv6_accept_ra_pinfo,
    .set  = set_ipv6_accept_ra_pinfo,
    .get  = get_ipv6_accept_ra_pinfo,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "ipv6_forwarding",
    .prep = prep_ipv6_forwarding,
    .set  = set_ipv6_forwarding,
    .get  = get_ipv6_forwarding,
    .ioctl_set = 0,
    .ioctl_get = 0,
  },
  { .name = "-ipv6_address",
    .prep = prep_ipaddr6_ioctl,
    .set  = remove_ipaddr6_ioctl,
    .get  = NULL,
    .ioctl_set = SIOCDIFADDR,
    .ioctl_get = 0,
  },
  { .name = "-ipv6_gateway",
    .prep = prep_default_gateway6,
    .set  = remove_gateway6_ioctl,
    .get  = NULL,
    .ioctl_set = SIOCDELRT,
    .ioctl_get = 0,
  },
  { .name = NULL, } /* Setting-up a guard */
};
#define HANDLER_COUNT ((sizeof(handlers)-1) / sizeof(handlers[0])) /* -1 is for the guard at the end of the array */

static int prep_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char macaddr_str[MACADDR_STR_LEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, macaddr_str, sizeof(macaddr_str)) < 0)
        errx(EXIT_FAILURE, "mac address parameter required for '%s'", handler->name);

    /* Be forgiving and if the user specifies an empty IP address, just skip
     * this request.
     */
    if (macaddr_str[0] == '\0')
        *context = NULL;
    else
        *context = strdup(macaddr_str);

    return 0;
}

struct ipv6_procfs_ctx {
    char token[10]; /* ProcFs atom string true/false/override */
};
#define member_size(type, member) sizeof( ((type *) 0)->member)

static int ipv6_read_integer_from_file(const struct ip_setting_handler *handler, struct netif *nb, const char *fname, int *val)
{
    FILE *f = NULL;

    (void) handler;

    if((f = fopen(fname, "r")) == NULL) {
        debug("Unable to open file '%s' for '%s'", fname, handler->name);
        nb->last_error = errno;
        return -1;
    }

    if(fscanf(f, "%d", val) < 0) {
        nb->last_error = EIO;
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

static int ipv6_write_integer_to_file(const struct ip_setting_handler *handler, struct netif *nb, const char *fname, const int val)
{
    FILE *f = NULL;

    (void) handler;

    if ((f = fopen(fname, "w")) == NULL) {
        debug("Unable to open file '%s' for '%s'", fname, handler->name);
        nb->last_error = errno;
        return -1;
    }

    if (fprintf(f, "%d", val) < 0) {
        nb->last_error = EIO;
        fclose(f);
        return -1;
    }

    fclose(f);

    return 0;
}


static int prep_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct ipv6_procfs_ctx *ac_ctx = *context = malloc(sizeof(struct ipv6_procfs_ctx));

    if(*context == NULL) {
        errx(EXIT_FAILURE, "Unable to allocate memory for '%s'", handler->name);
    }

    if ( erlcmd_decode_atom(nb->req, &nb->req_index, &ac_ctx->token[0], member_size(struct ipv6_procfs_ctx, token) ) < 0)
        errx(EXIT_FAILURE, "Autoconf value true/false required for '%s'", handler->name);

    return 0;
}

static int prep_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct ipv6_procfs_ctx *ac_ctx = *context = malloc(sizeof(struct ipv6_procfs_ctx));

    if(*context == NULL) {
        errx(EXIT_FAILURE, "Unable to allocate memory for '%s'", handler->name);
    }

    if ( erlcmd_decode_atom(nb->req, &nb->req_index, &ac_ctx->token[0], member_size(struct ipv6_procfs_ctx, token) ) < 0)
        errx(EXIT_FAILURE, "Autoconf value true/false required for '%s'", handler->name);

    return 0;
}

static int prep_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct ipv6_procfs_ctx *ac_ctx = *context = malloc(sizeof(struct ipv6_procfs_ctx));

    if(*context == NULL) {
        errx(EXIT_FAILURE, "Unable to allocate memory for '%s'", handler->name);
    }

    if ( erlcmd_decode_atom(nb->req, &nb->req_index, &ac_ctx->token[0], member_size(struct ipv6_procfs_ctx, token) ) < 0)
        errx(EXIT_FAILURE, "Autoconf value true/false required for '%s'", handler->name);

    return 0;
}

static int prep_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct ipv6_procfs_ctx *ac_ctx = *context = malloc(sizeof(struct ipv6_procfs_ctx));

    if(*context == NULL) {
        errx(EXIT_FAILURE, "Unable to allocate memory for '%s'", handler->name);
    }

    if ( erlcmd_decode_atom(nb->req, &nb->req_index, &ac_ctx->token[0], member_size(struct ipv6_procfs_ctx, token) ) < 0)
        errx(EXIT_FAILURE, "Autoconf value true/false required for '%s'", handler->name);

    return 0;
}

static int prep_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct ipv6_procfs_ctx *ac_ctx = *context = malloc(sizeof(struct ipv6_procfs_ctx));

    if(*context == NULL) {
        errx(EXIT_FAILURE, "Unable to allocate memory for '%s'", handler->name);
    }

    if ( erlcmd_decode_atom(nb->req, &nb->req_index, &ac_ctx->token[0], member_size(struct ipv6_procfs_ctx, token) ) < 0)
        errx(EXIT_FAILURE, "Autoconf value true/false required for '%s'", handler->name);

    return 0;
}

static int ipv6_bool_atom_to_integer(const struct ip_setting_handler *handler, struct netif *nb, const char *str, int *val) {
    if (strcmp(str, "true") == 0) {
        *val = 1;
    }
    else if (strcmp(str, "false") == 0) {
        *val = 0;
    }
    else {
        debug("Unsupported value of '%s' for '%s'", str, handler->name);
        return -1;
    }

    return 0;
}

static int ipv6_tri_state_atom_to_integer(const struct ip_setting_handler *handler, struct netif *nb, const char *str, int *val) {
    if (strcmp(str, "true") == 0) {
        *val = 1;
    }
    else if (strcmp(str, "false") == 0) {
        *val = 0;
    }
    else if (strcmp(str, "override") == 0) {
        *val = 2;
    }
    else {
        debug("Unsupported value of '%s' for '%s'", str, handler->name);
        return -1;
    }

    return 0;
}

static const char *ipv6_tri_state_integer_to_atom(const int val) {
    static const char *atoms[] = {
        "false",     /* 0 */
        "true",      /* 1 */
        "override",  /* 2 */
        ""           /* 3 */
    };

    switch(val) {
        case 0:
        case 1:
        case 2:
            return atoms[val];
        default:
            break;
    };

    return atoms[3];
}

static int ipv6_create_procfs_file_name(const struct ip_setting_handler *handler, struct netif *nb, char *dest, const size_t max_len, const char *ifname, const char *sys_fname)
{
    (void) handler;

    if ((unsigned int) snprintf(dest, max_len, "/proc/sys/net/ipv6/conf/%s/%s", ifname, sys_fname) >= max_len) {
        debug("The file name truncated! Setting not performed for '%s'", handler->name);
        nb->last_error = ENOMEM;
        return -1;
    }

    return 0;
}

/* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
 * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
#define NETIF_IPV6_PROC_FILENAME_MAXLEN (IFNAMSIZ+60+1)

static int set_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct ipv6_procfs_ctx *ac_ctx = (struct ipv6_procfs_ctx *) context;
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int autoconf = 0;

    if(ipv6_create_procfs_file_name(handler, nb, fname, sizeof(fname), ifname, "autoconf") < 0) {
        return -1;
    }

    if (ipv6_bool_atom_to_integer(handler, nb, ac_ctx->token, &autoconf) < 0) {
        nb->last_error = EOPNOTSUPP;
        return -1;
    }

    if(ipv6_write_integer_to_file(handler, nb, fname, autoconf) < 0){
        return -1;
    }

    return 0;
}

static int set_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct ipv6_procfs_ctx *ac_ctx = (struct ipv6_procfs_ctx *) context;
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int forwarding = 0;

    if(ipv6_create_procfs_file_name(handler, nb, fname, sizeof(fname), ifname, "forwarding") < 0) {
        return -1;
    }

    if (ipv6_bool_atom_to_integer(handler, nb, ac_ctx->token, &forwarding) < 0) {
        nb->last_error = EOPNOTSUPP;
        return -1;
    }

    if(ipv6_write_integer_to_file(handler, nb, fname, forwarding) < 0){
        return -1;
    }

    return 0;
}

static int set_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct ipv6_procfs_ctx *ac_ctx = (struct ipv6_procfs_ctx *) context;
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int disable = 0;

    if(ipv6_create_procfs_file_name(handler, nb, fname, sizeof(fname), ifname, "disable_ipv6") < 0) {
        return -1;
    }

    if (ipv6_bool_atom_to_integer(handler, nb, ac_ctx->token, &disable) < 0) {
        nb->last_error = EOPNOTSUPP;
        return -1;
    }

    if(ipv6_write_integer_to_file(handler, nb, fname, disable) < 0){
        return -1;
    }

    return 0;
}

static int set_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct ipv6_procfs_ctx *ac_ctx = (struct ipv6_procfs_ctx *) context;
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int accept_ra_pinfo = 0;

    if(ipv6_create_procfs_file_name(handler, nb, fname, sizeof(fname), ifname, "accept_ra_pinfo") < 0) {
        return -1;
    }

    if (ipv6_bool_atom_to_integer(handler, nb, ac_ctx->token, &accept_ra_pinfo) < 0) {
        nb->last_error = EOPNOTSUPP;
        return -1;
    }

    if(ipv6_write_integer_to_file(handler, nb, fname, accept_ra_pinfo) < 0){
        return -1;
    }

    return 0;
}

static int get_ipv6_autoconf(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    /* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
     * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int autoconf = 0;

    if(ipv6_create_procfs_file_name(handler, nb, &fname[0], sizeof(fname), ifname, "autoconf") < 0) {
        debug("[%s %d] generated fname = '%s'\r\n", __FILE__, __LINE__, fname);
        return -1;
    }

    if(ipv6_read_integer_from_file(handler, nb, fname, &autoconf) < 0) {
        return -1;
    }

    encode_kv_bool(nb, handler->name, autoconf);

    return 0;
}

static int get_ipv6_forwarding(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    /* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
     * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int forwarding = 0;

    if(ipv6_create_procfs_file_name(handler, nb, &fname[0], sizeof(fname), ifname, "forwarding") < 0) {
        debug("[%s %d] generated fname = '%s'\r\n", __FILE__, __LINE__, fname);
        return -1;
    }

    if(ipv6_read_integer_from_file(handler, nb, fname, &forwarding) < 0) {
        return -1;
    }

    encode_kv_bool(nb, handler->name, forwarding);

    return 0;
}

static int get_ipv6_disable(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    /* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
     * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int disable = 0;

    if(ipv6_create_procfs_file_name(handler, nb, &fname[0], sizeof(fname), ifname, "disable_ipv6") < 0) {
        debug("[%s %d] generated fname = '%s'\r\n", __FILE__, __LINE__, fname);
        return -1;
    }

    if(ipv6_read_integer_from_file(handler, nb, fname, &disable) < 0) {
        return -1;
    }

    encode_kv_bool(nb, handler->name, disable);

    return 0;
}

static int get_ipv6_accept_ra_pinfo(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    /* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
     * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int accept_ra_pinfo = 0;

    if(ipv6_create_procfs_file_name(handler, nb, &fname[0], sizeof(fname), ifname, "accept_ra_pinfo") < 0) {
        debug("[%s %d] generated fname = '%s'\r\n", __FILE__, __LINE__, fname);
        return -1;
    }

    if(ipv6_read_integer_from_file(handler, nb, fname, &accept_ra_pinfo) < 0) {
        return -1;
    }

    encode_kv_bool(nb, handler->name, accept_ra_pinfo);

    return 0;
}

static int set_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct ipv6_procfs_ctx *ac_ctx = (struct ipv6_procfs_ctx *) context;
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int accept_ra = 0;

    if(ipv6_create_procfs_file_name(handler, nb, fname, sizeof(fname), ifname, "accept_ra") < 0) {
        return -1;
    }

    if (ipv6_tri_state_atom_to_integer(handler, nb, ac_ctx->token, &accept_ra) < 0) {
        nb->last_error = EOPNOTSUPP;
        return -1;
    }

    if(ipv6_write_integer_to_file(handler, nb, fname, accept_ra) < 0){
        return -1;
    }

    return 0;
}

static int get_ipv6_accept_ra(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    /* The proc file's path is in the format: /proc/sys/net/ipv6/conf /<ifname>/accept_ra - hence we need
     * IFNAMSIZ + 34 bytes for the remainder '/proc/sys/net/ipv6/conf//accept_ra' +1 for '\0' string termination */
    char fname[NETIF_IPV6_PROC_FILENAME_MAXLEN] = {'\0', };
    int accept_ra = 0;

    if(ipv6_create_procfs_file_name(handler, nb, &fname[0], sizeof(fname), ifname, "accept_ra") < 0) {
        return -1;
    }

    if(ipv6_read_integer_from_file(handler, nb, fname, &accept_ra) < 0) {
        return -1;
    }

    encode_kv_atom(nb, handler->name, ipv6_tri_state_integer_to_atom(accept_ra) );

    return 0;
}


static int set_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    const char *macaddr_str = (const char *) context;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_family = AF_UNIX;
    unsigned char *mac = (unsigned char *) &ifr.ifr_hwaddr.sa_data;
    if (string_to_macaddr(macaddr_str, mac) < 0) {
        debug("Bad MAC address for '%s': %s", handler->name, macaddr_str);
        nb->last_error = EINVAL;
        return -1;
    }

    if (ioctl(nb->inet_fd, handler->ioctl_set, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

static int get_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, handler->ioctl_get, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for getting '%s': %s", handler->ioctl_get, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (addr->sin_family == AF_UNIX) {
        encode_kv_macaddr(nb, handler->name, (unsigned char *) &ifr.ifr_hwaddr.sa_data);
    } else {
        debug("Got unexpected sin_family %d for '%s'", addr->sin_family, handler->name);
        nb->last_error = EINVAL;
        return -1;
    }
    return 0;
}

static int prep_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char ipaddr[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    /* Be forgiving and if the user specifies an empty IP address, just skip
     * this request.
     */
    if (ipaddr[0] == '\0')
        *context = NULL;
    else
        *context = strdup(ipaddr);

    return 0;
}

static int prep_ipaddr(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    #define PREFIX_LEN  (3) /* ':' + 2 bytes i.e. 1.2.3.4:32 */
    char ipaddr[INET_ADDRSTRLEN+PREFIX_LEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr, INET_ADDRSTRLEN+PREFIX_LEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);


    /* Be forgiving and if the user specifies an empty IP address, just skip
     * this request.
     */
    if (ipaddr[0] == '\0')
        *context = NULL;
    else
      *context = strdup(ipaddr);

    return 0;
}


#define access_setting_handler(ptr) ((const struct ip_setting_handler *) ptr)
static int prep_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    struct in6_ifreq *ifr6  = malloc(sizeof(struct in6_ifreq));
    char *prefix_ptr = (void *) NULL;
    char ipaddr[INET6_ADDRSTRLEN] = {0, };

    if(ifr6 == NULL) {
        debug("Unable to allocate memory for '%s'", handler->name);
        nb->last_error = ENOMEM;
        return -1;
    }

    *context = (void *) ifr6;

    memset(ifr6, 0, sizeof(*ifr6));

    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr, INET6_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    /* Let's check whether prefix was provided as part of the address */
    prefix_ptr = strchr(ipaddr, (int) '/');

    if(prefix_ptr != NULL) {
        char *end_ptr   = NULL;
        long int retval = 0;

        /* Let's terminate the preceeding IPv6 address so we would be able to parse it later on */
        *prefix_ptr = '\0';

        /* Parse the prefix */
        retval = strtol(&prefix_ptr[1], &end_ptr, 0);

        /* There were no digits to parse */
        if(&prefix_ptr[1] == end_ptr) {
            nb->last_error = EINVAL;
            return -1;
        }

        /* Of course prefix cannot be a negative number and longer than the IPv6 address itself */
        if((retval < 0) || (retval > 128)) {
            nb->last_error = EINVAL;
            return -1;
        }

        ifr6->ifr6_prefixlen = (int) retval;
    }

    if (inet_pton(AF_INET6, ipaddr, &ifr6->ifr6_addr) <= 0) {
        debug("Bad IP address for '%s': %s", handler->name, ipaddr);
        nb->last_error = EINVAL;
        return -1;
    }

    /* We are restoring the original '/' caracter we temporarily replaced with '\0' */
    *prefix_ptr = '/';

    return 0;
}

static int set_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    const char *ipaddr = (const char *) context;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;

    info("[%s %d %s]: address = '%s'\r\n", __FILE__, __LINE__, __FUNCTION__, ipaddr);

    addr->sin_family = AF_INET;

    if (inet_pton(AF_INET, ipaddr, &addr->sin_addr) <= 0) {
        error("Bad IP address for '%s': %s", handler->name, ipaddr);
        nb->last_error = EINVAL;
        return -1;
    }

    if (ioctl(nb->inet_fd, handler->ioctl_set, &ifr) < 0) {
        error("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

static int remove_ipaddr(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
  const char *ipaddr = (const char *) context;
  char *prefix = (char *) strchr(context, ':');

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

  struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
  struct nlmsghdr    *nlh  = mnl_nlmsg_put_header(nb->nlbuf);
  struct ifaddrmsg   *ipm  = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));;

  int seq = nb->seq++;
  int ret = 0;

  nlh->nlmsg_type  = RTM_DELADDR;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq   = seq;

  if(prefix != NULL) {
    /* Prefix length attached */
    *prefix = '\0';
    prefix++;
    ipm->ifa_prefixlen = atoi(prefix);
    debug("[%s %d]: ipm->ifa_prefixlen = %d\r\n", __FILE__, __LINE__, ipm->ifa_prefixlen);
  }

  ipm->ifa_family = AF_INET;
  ipm->ifa_flags = 0;
  ipm->ifa_scope = 0;

  debug("[%s %d]: remove_ipaddr for '%s'\r\n", __FILE__, __LINE__, ifname);

  addr->sin_family = AF_INET;
  if (inet_pton(AF_INET, ipaddr, &addr->sin_addr) <= 0) {
    debug("Bad IP address for '%s': %s", handler->name, ipaddr);
    nb->last_error = EINVAL;
    return -1;
  }

  mnl_attr_put_u32(nlh, IFA_ADDRESS, addr->sin_addr.s_addr);

  if (ifname) {
    ipm->ifa_index = ifname_to_index(nb, ifname);

    if (!ipm->ifa_index) {
      debug("[%s %d]: No such device: '%s'\r\n", __FILE__, __LINE__, ifname);
      nb->last_error = ENODEV;
      return -1;
    }
  }

  if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0) {
    debug("[%s %d]: mnl_socket_sendto", __FILE__, __LINE__);
    err(EXIT_FAILURE, "mnl_socket_sendto");
  }

  ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
  if (ret < 0) {
    debug("[%s %d]: mnl_socket_recvfrom", __FILE__, __LINE__);
    err(EXIT_FAILURE, "mnl_socket_recvfrom");
  }

  {
    unsigned int portid = mnl_socket_get_portid(nb->nl);

    debug("[%s %d]: mnl_cb_run(ret = %d; seq = %d; portid = %d\r\n", __FILE__, __LINE__, ret, seq, portid);

    ret = mnl_cb_run(nb->nlbuf, ret, seq, portid, NULL, NULL);

    if (ret < 0) {
      debug("[%s %d]: mnl_cb_run ret = %d", __FILE__, __LINE__, ret);
      return 0;
      //err(EXIT_FAILURE, "mnl_cb_run");
    }
  }

  debug("remove_ipaddr ok %s", ifname);

  return 0;
}

static int get_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, handler->ioctl_get, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for getting '%s': %s. Skipping...", handler->ioctl_get, handler->name, strerror(errno));
        encode_kv_string(nb, handler->name, "");
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (addr->sin_family == AF_INET) {
        char addrstr[INET_ADDRSTRLEN];
        if (!inet_ntop(addr->sin_family, &addr->sin_addr, addrstr, sizeof(addrstr))) {
            debug("inet_ntop failed for '%s'? : %s", handler->name, strerror(errno));
            nb->last_error = errno;
            return -1;
        }
        encode_kv_string(nb, handler->name, addrstr);
    } else {
        debug("Got unexpected sin_family %d for '%s'", addr->sin_family, handler->name);
        nb->last_error = EINVAL;
        return -1;
    }
    return 0;
}

static int get_if_index(struct netif *nb, const char *ifname, int * const if_index)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, SIOGIFINDEX, &ifr) < 0) {
        nb->last_error = errno;
        return -1;
    }

    *if_index = ifr.ifr_ifindex;
    return 0;
}

#if defined(DEBUG)
static void byte_debug(char * caption, void *buf, int len) {
    int i = 0;
    fprintf(stderr, "======================== %s ========================\r\n", caption);
    for(; i < len; i++)
        fprintf(stderr, "%02x ", (int) ((unsigned char *) buf)[i]);
}
#else
#   define byte_debug(caption, buf, len)
#endif /* DEBUG */

static int set_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct in6_ifreq *ifr6 = (struct in6_ifreq *) context;

    debug("[%s %d]: set_ipaddr6_ioctl\r\n", __FILE__, __LINE__);

    byte_debug("ifr6_addr", &ifr6->ifr6_addr, sizeof(ifr6->ifr6_addr));

    if(get_if_index(nb, ifname, &ifr6->ifr6_ifindex) != 0) {
        debug("Unable to obtain netif index '%s': %d", handler->name, ifr6->ifr6_ifindex);
        nb->last_error = EINVAL;
        return -1;
    }

    debug("netif index '%s': %d", handler->name, ifr6->ifr6_ifindex);

    if (ioctl(nb->inet6_fd, handler->ioctl_set, ifr6) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

static int remove_ipaddr6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    struct in6_ifreq *ifr6 = (struct in6_ifreq *) context;

    debug("[%s %d]: remove_ipaddr6_ioctl\r\n", __FILE__, __LINE__);

    byte_debug("ifr6_addr", &ifr6->ifr6_addr, sizeof(ifr6->ifr6_addr));

    if(get_if_index(nb, ifname, &ifr6->ifr6_ifindex) != 0) {
        debug("Unable to obtain netif index '%s': %d", handler->name, ifr6->ifr6_ifindex);
        nb->last_error = EINVAL;
        return -1;
    }

    debug("netif index '%s': %d", handler->name, ifr6->ifr6_ifindex);

    if (ioctl(nb->inet6_fd, handler->ioctl_set, ifr6) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

#define SCOPE_STR_MAX_LEN (16)

static char * get_ip6_address_scope(char * restrict scope_str, const struct in6_addr *addr) {
  if(IN6_IS_ADDR_LINKLOCAL(addr)) {
      return strncpy(scope_str, "link-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_SITELOCAL(addr)) {
      return strncpy(scope_str, "site-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_UNSPECIFIED(addr)) {
      return strncpy(scope_str, "unspecified", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_LOOPBACK(addr)) {
      return strncpy(scope_str, "loopback", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_V4MAPPED(addr)) {
      return strncpy(scope_str, "v4-mapped", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_V4COMPAT(addr)) {
      return strncpy(scope_str, "v4-compat", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_MC_NODELOCAL(addr)) {
      return strncpy(scope_str, "node-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_MC_LINKLOCAL(addr)) {
      return strncpy(scope_str, "link-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_MC_SITELOCAL(addr)) {
      return strncpy(scope_str, "site-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_MC_ORGLOCAL(addr)) {
      return strncpy(scope_str, "org-local", SCOPE_STR_MAX_LEN);
  } else if(IN6_IS_ADDR_MC_GLOBAL(addr)) {
      return strncpy(scope_str, "global", SCOPE_STR_MAX_LEN);
  } else {
      return strncpy(scope_str, "global", SCOPE_STR_MAX_LEN);
  }
  return scope_str;
}

/* Encodes the erlang list of IPv6 addresses' strings in the form of [ a | [b | [c] ] bound to a network interface if the ifname name */
static int get_ipaddr6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    FILE *f = fopen("/proc/net/if_inet6", "r");
    struct in6_addr ip6 = in6addr_any;
    char parsed_ifname[IFNAMSIZ]       = {'\0', };
    char addr_scope[SCOPE_STR_MAX_LEN] = {'\0', };
    unsigned int prefix = 0;
    unsigned int scope  = 0;

    if(f == NULL) {
        debug("[%s %d]: Unable to open file for reading!!", __FILE__, __LINE__);
        nb->last_error = errno;
        return -1;
    }
    /* A sample entry for an interface fe80000000000000020c29fffe9c009e 02 40 20 80    eth0 */
    /* 00000000000000000000000000000001 01 80 10 80 lo
       +------------------------------+ ++ ++ ++ ++ ++
       |                                |  |  |  |  |
       1                                2  3  4  5  6

       1. IPv6 address displayed in 32 hexadecimal chars without colons as separator
       2. Netlink device number (interface index) in hexadecimal (see ”ip addr” , too)
       3. Prefix length in hexadecimal
       4. Scope value (see kernel source ” include/net/ipv6.h” and ”net/ipv6/addrconf.c” for more)
       5. Interface flags (see ”include/linux/rtnetlink.h” and ”net/ipv6/addrconf.c” for more)
       6. Device name
    */
    ei_encode_atom(nb->resp, &nb->resp_index, handler->name);
    while(19 == fscanf(f, "%2hhx%2hhx%2hhx%2hhx""%2hhx%2hhx%2hhx%2hhx""%2hhx%2hhx%2hhx%2hhx""%2hhx%2hhx%2hhx%2hhx""%*x %x %x %*x %s",
                    &ip6.s6_addr[0],
                    &ip6.s6_addr[1],
                    &ip6.s6_addr[2],
                    &ip6.s6_addr[3],
                    &ip6.s6_addr[4],
                    &ip6.s6_addr[5],
                    &ip6.s6_addr[6],
                    &ip6.s6_addr[7],
                    &ip6.s6_addr[8],
                    &ip6.s6_addr[9],
                    &ip6.s6_addr[10],
                    &ip6.s6_addr[11],
                    &ip6.s6_addr[12],
                    &ip6.s6_addr[13],
                    &ip6.s6_addr[14],
                    &ip6.s6_addr[15],
                    &prefix, &scope, &parsed_ifname[0])) {
        char address[INET6_ADDRSTRLEN]  = {'\0', };
        char prefix_str[MAX_PREFIX_LEN] = {'\0', };

        if(strcmp(parsed_ifname, ifname) != 0) {
            debug("[%s %d]: Parsed ifname '%s' neq ifname = '%s' skipping...", __FILE__, __LINE__, parsed_ifname, ifname);
            continue;
        }

        if(inet_ntop(AF_INET6, &ip6, address, sizeof(address)) == NULL) {
            debug("[%s %d]: Invalid IP address skipping...", __FILE__, __LINE__);
            continue;
        } else {
          /* Decode Scope */
          (void) get_ip6_address_scope(&addr_scope[0], &ip6);
          debug("[%s %d]: Address scope = '%s'", __FILE__, __LINE__, addr_scope);
        }

        snprintf(prefix_str, sizeof(prefix_str), "/%d", prefix);

        debug("[%s %d]: address = '%s'", __FILE__, __LINE__, address);
        debug("[%s %d]: prefix  = '%s'", __FILE__, __LINE__, prefix_str);
        strcat(address, prefix_str);
        debug("[%s %d]: Result address = '%s'", __FILE__, __LINE__, address);
        /* Let's concat the prefix length in the IPv6 address string */
        ei_encode_list_header(nb->resp, &nb->resp_index, 1);
        ei_encode_map_header(nb->resp, &nb->resp_index, 2);
        ei_encode_atom(nb->resp, &nb->resp_index, "address");
        encode_string(nb->resp, &nb->resp_index, address);
        ei_encode_atom(nb->resp, &nb->resp_index, "scope");
        encode_string(nb->resp, &nb->resp_index, addr_scope);
    } /* while (19 == fscanf(...) */
    ei_encode_empty_list(nb->resp, &nb->resp_index);

    fclose(f);

    return 0;
}

static int remove_all_gateways(struct netif *nb, const char *ifname)
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
                nb->last_error = errno;
                return -1;
            }
        }
    }
}

static int remove_gateway6(struct netif *nb, const char *ifname, const struct in6_addr *gw_addr, const unsigned short flags)
{
  struct in6_rtmsg route = {0, };
  struct in6_addr *gw  = (struct in6_addr *) &route.rtmsg_gateway;
  struct in6_addr *dst = (struct in6_addr *) &route.rtmsg_dst;
  int rc = 0;

  *gw  = *gw_addr;
  *dst = in6addr_any;

  route.rtmsg_dst_len = 0;
  route.rtmsg_ifindex = ifname_to_index(nb, ifname);
  route.rtmsg_flags   = RTF_UP | RTF_GATEWAY | flags; /* if the RTF_GATEWAY flag is set the gateway ip must exactly mach the one in the fib table */
  route.rtmsg_metric  = 256;

  rc = ioctl(nb->inet6_fd, SIOCDELRT, &route);

  debug("Removing GW returned rc = %d\r\n", rc);

  if (rc  < 0) {
    if (errno == ESRCH) {
      return 0;
    } else {
      nb->last_error = errno;
      debug("Removing GW returnt rc = %d; errno = %d '%s'\r\n", rc, errno, strerror(errno));
      return -1;
    }
  }

  return 0;
}

static int remove_all_gateways6(struct netif *nb, const char *ifname)
{
    struct in6_rtmsg route = {0, };
    struct in6_addr *gw  = (struct in6_addr *) &route.rtmsg_gateway;
    struct in6_addr *dst = (struct in6_addr *) &route.rtmsg_dst;

    *gw  = in6addr_any;
    *dst = in6addr_any;

    route.rtmsg_dst_len = 0;
    route.rtmsg_ifindex = ifname_to_index(nb, ifname);
    route.rtmsg_flags   = RTF_UP; /* if the RTF_GATEWAY flag is set the gateway ip must exactly mach the one in the fib table */
    route.rtmsg_metric  = 0;

    /* There may be more than one gateway. Remove all of them. */
    for (;;) {
        int rc = ioctl(nb->inet6_fd, SIOCDELRT, &route);
        debug("Removing GW returnt rc = %d\r\n", rc);
        if (rc < 0) {
            if (errno == ESRCH) {
                return 0;
            } else {
                nb->last_error = errno;
                debug("Removing GW returnt rc = %d\r\n", rc);
                return -1;
            }
        }
    }
}

static int add_default_gateway(struct netif *nb, const char *ifname, const char *gateway_ip)
{
  struct nlmsghdr *nlh = mnl_nlmsg_put_header(nb->nlbuf);
  struct rtmsg    *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));;

  int seq = nb->seq++;
  int ret = 0;

  memset(rtm, 0, sizeof(*rtm));

  nlh->nlmsg_type = RTM_NEWROUTE;

  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
  nlh->nlmsg_seq   = seq;

  rtm->rtm_family   = AF_INET;
  rtm->rtm_table    = RT_TABLE_MAIN;
  rtm->rtm_scope    = RT_SCOPE_UNIVERSE;
  rtm->rtm_protocol = RTPROT_BOOT;
  rtm->rtm_type     = RTN_UNICAST;
  rtm->rtm_flags    = RTNH_F_ONLINK;

  {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, gateway_ip, &addr.sin_addr) <= 0) {
      error("Bad IP address for the default gateway: %s", gateway_ip);
      nb->last_error = EINVAL;
      return -1;
    }

    mnl_attr_put_u32(nlh, RTA_GATEWAY, addr.sin_addr.s_addr);
  }

  if (ifname) {
    int idx = ifname_to_index(nb, ifname);

    if (!idx) {
      debug("[%s %d]: No such device: '%s'\r\n", __FILE__, __LINE__, ifname);
      nb->last_error = ENODEV;
      return -1;
    }

    mnl_attr_put_u32(nlh, RTA_OIF, idx);
  }


  if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0) {
    error("[%s %d %s]: mnl_socket_sendto", __FILE__, __LINE__, __FUNCTION__);
    err(EXIT_FAILURE, "mnl_socket_sendto");
  }

  ret = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
  if (ret < 0) {
    error("[%s %d %s]: mnl_socket_recvfrom", __FILE__, __LINE__, __FUNCTION__);

    err(EXIT_FAILURE, "mnl_socket_recvfrom");
  }

  {
    unsigned int portid = mnl_socket_get_portid(nb->nl);
    ret = mnl_cb_run(nb->nlbuf, ret, seq, portid, NULL, NULL);

    if (ret < 0) {
      error("[%s %d %s]: mnl_cb_run", __FILE__, __LINE__, __FUNCTION__);
      err(EXIT_FAILURE, "mnl_cb_run");
    }
  }

  debug("add_default_gateway ok %s", ifname);
  return 0;
}

static int prep_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char gateway[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, gateway, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    *context = strdup(gateway);
    return 0;
}

static int prep_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char gateway[INET6_ADDRSTRLEN] = {'\0', };
    if (erlcmd_decode_string(nb->req, &nb->req_index, gateway, INET6_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    *context = strdup(gateway);
    return 0;
}

static int set_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    (void) handler;
    const char *gateway = context;

    /* If no gateway was specified, then we're done. */
    if (*gateway == '\0')
        return 0;

    return add_default_gateway6(nb, ifname, gateway, 0);
}

static int remove_gateway6_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
  (void) handler;
  const char *gateway_ip = context;
  struct in6_addr gw     = in6addr_any;

  /* If IPv6 gateway's address is an empty string "", then we remove all */
  if (*gateway_ip == '\0')
    return remove_all_gateways6(nb, ifname);

  if (inet_pton(AF_INET6, gateway_ip, (void *) &gw) <= 0) {
    error("Bad IP address for the default gateway v6: %s", gateway_ip);
    nb->last_error = EINVAL;
    return -1;
  }

  /* If IPv6 gateway-for-removal's address is ANY i.e. :: all default gateways ar targetted for removal */
  if(memcmp(&gw, &in6addr_any, sizeof(struct in6_addr)) == 0)
    return remove_all_gateways6(nb, ifname);

  return remove_gateway6(nb, ifname, &gw, 0);
}

static int get_default_gateway6(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    int oif = ifname_to_index(nb, ifname);
    char gateway_ip[INET6_ADDRSTRLEN] = {'\0', };

    if (oif < 0)
        return -1;

    find_default_gateway6(nb, oif, gateway_ip);
    debug("[%s %d]: gateway_ip = '%s'\r\n", __FILE__, __LINE__, gateway_ip);

    /* If the gateway isn't found, then the empty string is what we want. */
    encode_kv_string(nb, handler->name, gateway_ip);
    return 0;
}

static int add_default_gateway6(struct netif *nb, const char *ifname, const char *gateway_ip, const unsigned short flags)
{
    struct in6_rtmsg route = {0, };
    struct in6_addr *dst = (struct in6_addr *) &route.rtmsg_dst;
    struct in6_addr *gw  = (struct in6_addr *) &route.rtmsg_gateway;

    *dst = in6addr_any;

    if (inet_pton(AF_INET6, gateway_ip, (void *) gw) <= 0) {
        error("Bad IP address for the default gateway v6: %s", gateway_ip);
        nb->last_error = EINVAL;
        return -1;
    }

    route.rtmsg_dst_len = 0; /* router does not have to have a prefix */
    route.rtmsg_flags   = RTF_UP | RTF_GATEWAY | flags;
    route.rtmsg_metric  = 1;
    route.rtmsg_ifindex = ifname_to_index(nb, ifname);

    int rc = ioctl(nb->inet6_fd, SIOCADDRT, &route);
    if (rc < 0 && errno != EEXIST) {
        error("IOCTL failed for the default gateway v6: %s", gateway_ip);
        nb->last_error = errno;
        return -1;
    }
    return 0;
}

static int set_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    (void) handler;
    const char *gateway = context;

    info("set_default_gateway %s; gateway = '%s'", ifname, gateway);

    /* Before one can be set, any configured gateways need to be removed. */
    if (remove_all_gateways(nb, ifname) < 0) {
        error("remove_all_gateways failed for '%s' : %s", handler->name, gateway);
        return -1;
    }

    /* If no gateway was specified, then we're done. */
    if (*gateway == '\0')
        return 0;

    return add_default_gateway(nb, ifname, gateway);
}

static int ifname_to_index(struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, SIOCGIFINDEX, &ifr) < 0) {
        nb->last_error = errno;
        return -1;
    }
    return ifr.ifr_ifindex;
}

static int get_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
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


static size_t netif_count_rw_handlers()
{
  const struct ip_setting_handler *handler;
  size_t count = 0;

  for(handler = &handlers[0]; handler->name != NULL; handler++) {
    if(handler->get != NULL) {
      count++;
    }
  }

  return count;
}

static void netif_handle_get(struct netif *nb,
                                 const char *ifname)
{
  start_response(nb);
  {
    int original_resp_index = nb->resp_index;
    size_t i = 0;

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);
    ei_encode_atom(nb->resp, &nb->resp_index, "ok");
    ei_encode_map_header(nb->resp, &nb->resp_index, netif_count_rw_handlers());

    nb->last_error = 0;

    for (; i < HANDLER_COUNT; i++) {
      const struct ip_setting_handler *handler = &handlers[i];

      if(handler->get == NULL) /* There are handlers that are for write only operations and do not implement get function */
        continue;
      if (handler->get(handler, nb, ifname) < 0)
        break;
    }

    if (nb->last_error) {
      nb->resp_index = original_resp_index;
      erlcmd_encode_errno_error(nb->resp, &nb->resp_index, nb->last_error);
    }

    send_response(nb);
  }
}

static const struct ip_setting_handler *find_handler(const char *name)
{
  for (size_t i = 0; i < HANDLER_COUNT; i++) {
    const struct ip_setting_handler *handler = &handlers[i];
    if (strcmp(handler->name, name) == 0)
      return handler;
  }
  return NULL;
}

static void netif_handle_set(struct netif *nb,
                             const char *ifname)
{
  void *handler_context[HANDLER_COUNT] = { NULL, };
  int arity = 0;

  start_response(nb);

  nb->last_error = 0;

  if (ei_decode_map_header(nb->req, &nb->req_index, &arity) < 0)
     errx(EXIT_FAILURE, "setting attributes requires a map");

  // Parse all options
  for (int i = 0; i < arity && nb->last_error == 0; i++) {
    struct ip_setting_handler *handler = NULL;
    char name[32] = {'\0', };

    if (erlcmd_decode_atom(nb->req, &nb->req_index, name, sizeof(name)) < 0)
      errx(EXIT_FAILURE, "error in map encoding");

    // Look up the option. If we don't know it, silently ignore it so that
    // the caller can pass in maps that contain options for other code.
    handler = (struct ip_setting_handler *) find_handler(name);

    debug("%s %d]: handler for '%s' = %p\r\n", __FILE__, __LINE__, name, (void *) handler);

    if (handler != NULL) {
      handler->prep(handler, nb, &handler_context[handler - handlers]);
    } else {
      debug("%s %d]: No known handler for '%s' = %p! Skipping term...\r\n", __FILE__, __LINE__, name, (void *) handler);
      ei_skip_term(nb->req, &nb->req_index);
    }
  }

  // If no errors, then set everything
  if (!nb->last_error) {
    size_t i;
    // Order is important: see note on handlers
    for (i = 0; i < HANDLER_COUNT; i++) {
      if (handler_context[i]) {
        handlers[i].set(&handlers[i], nb, ifname, handler_context[i]);
      }
    }
  }

  /* Let's free all contextes that had been allocated above by the prep handlers */
  {
    size_t i;
    for (i = 0; i < HANDLER_COUNT; i++) {
      if (handler_context[i]) {
        free(handler_context[i]);
        handler_context[i] = NULL;
      }
    }
  }

  debug("[%s %d]: last_error = %d\r\n", __FILE__, __LINE__, nb->last_error);

  // Encode and send the response
  if (nb->last_error)
    erlcmd_encode_errno_error(nb->resp, &nb->resp_index, nb->last_error);
  else
    erlcmd_encode_ok(nb->resp, &nb->resp_index);

  send_response(nb);
}

static void netif_request_handler(const char *req, void *cookie)
{
    struct netif *nb = (struct netif *) cookie;
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

    if (strcmp(cmd, "interfaces") == 0) {
        debugf("interfaces");
        netif_handle_interfaces(nb);
    } else if (strcmp(cmd, "status") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "status requires ifname");
        debug("ifinfo: %s", ifname);
        netif_handle_status(nb, ifname);
    } else if (strcmp(cmd, "ifup") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "ifup requires ifname");
        debug("ifup: %s", ifname);
        netif_set_ifflags(nb, ifname, IFF_UP, IFF_UP);
    } else if (strcmp(cmd, "ifdown") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "ifdown requires ifname");
        debug("ifdown: %s", ifname);
        netif_set_ifflags(nb, ifname, 0, IFF_UP);
    } else if (strcmp(cmd, "setup") == 0) {
        if (ei_decode_tuple_header(nb->req, &nb->req_index, &arity) < 0 ||
                arity != 2 ||
                erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0) {
            debugf("setup requires {ifname, parameters}");
            errx(EXIT_FAILURE, "setup requires {ifname, parameters}");
        }
        debug("set: %s", ifname);
        netif_handle_set(nb, ifname);
    } else if (strcmp(cmd, "settings") == 0) {
        if (erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "settings requires ifname");
        debug("get: %s", ifname);
        netif_handle_get(nb, ifname);
    } else
        errx(EXIT_FAILURE, "unknown command: %s", cmd);
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    struct netif nb;
    netif_init(&nb);

    struct erlcmd handler;
    erlcmd_init(&handler, netif_request_handler, &nb);

    for (;;) {
        struct pollfd fdset[3];

        fdset[0].fd = STDIN_FILENO;
        fdset[0].events = POLLIN;
        fdset[0].revents = 0;

        fdset[1].fd = mnl_socket_get_fd(nb.nl);
        fdset[1].events = POLLIN;
        fdset[1].revents = 0;

        fdset[2].fd = mnl_socket_get_fd(nb.nl_uevent);
        fdset[2].events = POLLIN;
        fdset[2].revents = 0;

        int rc = poll(fdset, 3, -1);
        if (rc < 0) {
            // Retry if EINTR
            if (errno == EINTR)
                continue;

            err(EXIT_FAILURE, "poll");
        }

        if (fdset[0].revents & (POLLIN | POLLHUP))
            erlcmd_process(&handler);
        if (fdset[1].revents & (POLLIN | POLLHUP))
            nl_route_process(&nb);
        if (fdset[2].revents & (POLLIN | POLLHUP))
            nl_uevent_process(&nb);
    }

    netif_cleanup(&nb);
    return 0;
}
