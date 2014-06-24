#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "erlcmd.h"

#define DEBUG
#ifdef DEBUG
#define debug(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\r\n"); } while(0)
#else
#define debug(...)
#endif

struct net_basic {
    struct mnl_socket *nl;
    char nlbuf[8192]; // See MNL_SOCKET_BUFFER_SIZE
    char resp[ERLCMD_BUF_SIZE];
    int resp_index;
    int seq;
};

static void net_basic_init(struct net_basic *nb)
{
    memset(nb, 0, sizeof(*nb));
    nb->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nb->nl)
        errx(EXIT_FAILURE, "mnl_socket_open");

    if (mnl_socket_bind(nb->nl, RTMGRP_LINK, MNL_SOCKET_AUTOPID) < 0)
        errx(EXIT_FAILURE, "mnl_socket_bind");

    nb->seq = 1;
}

static void net_basic_cleanup(struct net_basic *nb)
{
    mnl_socket_close(nb->nl);
    nb->nl = NULL;
}

static int collect_attrs(const struct nlattr *attr, void *data)
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

static void encode_long(struct net_basic *nb, const char *key, long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_long(nb->resp, &nb->resp_index, value);
}

static void encode_ulong(struct net_basic *nb, const char *key, unsigned long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_ulong(nb->resp, &nb->resp_index, value);
}
static void encode_bool(struct net_basic *nb, const char *key, int value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_boolean(nb->resp, &nb->resp_index, value);
}
static void encode_string(struct net_basic *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_string(nb->resp, &nb->resp_index, str);
}

static void encode_stats(struct net_basic *nb, const char *key, struct nlattr *attr)
{
    struct rtnl_link_stats *stats = (struct rtnl_link_stats *) mnl_attr_get_payload(attr);

    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_map_header(nb->resp, &nb->resp_index, 10);
    encode_ulong(nb, "rx_packets", stats->rx_packets);
    encode_ulong(nb, "tx_packets", stats->tx_packets);
    encode_ulong(nb, "rx_bytes", stats->rx_bytes);
    encode_ulong(nb, "tx_bytes", stats->tx_bytes);
    encode_ulong(nb, "rx_errors", stats->rx_errors);
    encode_ulong(nb, "tx_errors", stats->tx_errors);
    encode_ulong(nb, "rx_dropped", stats->rx_dropped);
    encode_ulong(nb, "tx_dropped", stats->tx_dropped);
    encode_ulong(nb, "multicast", stats->multicast);
    encode_ulong(nb, "collisions", stats->collisions);
}

static int net_basic_build_ifinfo(const struct nlmsghdr *nlh, void *data)
{
    struct net_basic *nb = (struct net_basic *) data;
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    if (mnl_attr_parse(nlh, sizeof(*ifm), collect_attrs, tb) != MNL_CB_OK) {
        debug("Error from mnl_attr_parse");
        return MNL_CB_ERROR;
    }

    int count = 7; // Number of fields that we always encode
    int i;
    for (i = 0; i <= IFLA_MAX; i++)
        if (tb[i])
            count++;

    ei_encode_map_header(nb->resp, &nb->resp_index, count);

    encode_long(nb, "index", ifm->ifi_index);

    ei_encode_atom(nb->resp, &nb->resp_index, "type");
    ei_encode_atom(nb->resp, &nb->resp_index, ifm->ifi_type == ARPHRD_ETHER ? "ethernet" : "other");

    encode_bool(nb, "is_up", ifm->ifi_flags & IFF_UP);
    encode_bool(nb, "is_broadcast", ifm->ifi_flags & IFF_BROADCAST);
    encode_bool(nb, "is_running", ifm->ifi_flags & IFF_RUNNING);
    encode_bool(nb, "is_lower_up", ifm->ifi_flags & IFF_LOWER_UP);
    encode_bool(nb, "is_multicast", ifm->ifi_flags & IFF_MULTICAST);

    if (tb[IFLA_MTU])
        encode_ulong(nb, "mtu", mnl_attr_get_u32(tb[IFLA_MTU]));
    if (tb[IFLA_IFNAME])
        encode_string(nb, "ifname", mnl_attr_get_str(tb[IFLA_IFNAME]));
    if (tb[IFLA_ADDRESS]) {
        ei_encode_atom(nb->resp, &nb->resp_index, "mac_address");
        ei_encode_binary(nb->resp, &nb->resp_index, mnl_attr_get_payload(tb[IFLA_ADDRESS]), mnl_attr_get_payload_len(tb[IFLA_ADDRESS]));
    }
    if (tb[IFLA_BROADCAST]) {
        ei_encode_atom(nb->resp, &nb->resp_index, "mac_broadcast");
        ei_encode_binary(nb->resp, &nb->resp_index, mnl_attr_get_payload(tb[IFLA_BROADCAST]), mnl_attr_get_payload_len(tb[IFLA_BROADCAST]));
    }
    if (tb[IFLA_LINK])
        encode_ulong(nb, "link", mnl_attr_get_u32(tb[IFLA_LINK]));
    if (tb[IFLA_OPERSTATE])
        encode_string(nb, "operstate", mnl_attr_get_str(tb[IFLA_OPERSTATE]));
    if (tb[IFLA_STATS])
        encode_stats(nb, "stats", tb[IFLA_STATS]);

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
    ei_encode_version(nb->resp, &nb->resp_index);

    // The only notifications are interface updates.
    if (mnl_cb_run(buf, bytecount, 0, 0, net_basic_build_ifinfo, nb) <= 0)
        errx(EXIT_FAILURE, "mnl_cb_run");

    erlcmd_send(nb->resp, nb->resp_index);
}

static void net_basic_handle_interfaces(struct net_basic *nb)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        err(EXIT_FAILURE, "socket");

    struct ifreq ifr;
    ifr.ifr_ifindex = 1;
    while (ioctl(fd, SIOCGIFNAME, &ifr) >= 0) {
        debug("Found interface %s.", ifr.ifr_name);
        ei_encode_list_header(nb->resp, &nb->resp_index, 1);
        ei_encode_string(nb->resp, &nb->resp_index, ifr.ifr_name);
        ifr.ifr_ifindex++;
    }
    close(fd);
    ei_encode_empty_list(nb->resp, &nb->resp_index);
}

static void net_basic_handle_ifinfo(struct net_basic *nb,
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
        debug("error from mnl_socket_recv or mnl_cb_run?");
        nb->resp_index = original_resp_index;
        ei_encode_atom(nb->resp, &nb->resp_index, "error");
    }
}

static void net_basic_request_handler(const char *req, void *cookie)
{
    struct net_basic *nb = (struct net_basic *) cookie;

    // Commands are of the form {Command, Arguments}:
    // { atom(), term() }
    int req_index = sizeof(uint16_t);
    if (ei_decode_version(req, &req_index, NULL) < 0)
        errx(EXIT_FAILURE, "Message version issue?");

    int arity;
    if (ei_decode_tuple_header(req, &req_index, &arity) < 0 ||
            arity != 2)
        errx(EXIT_FAILURE, "expecting {cmd, args} tuple");

    char cmd[MAXATOMLEN];
    if (ei_decode_atom(req, &req_index, cmd) < 0)
        errx(EXIT_FAILURE, "expecting command atom");
    debug("net_basic_request_handler: %s", cmd);

    nb->resp_index = sizeof(uint16_t); // Space for payload size
    ei_encode_version(nb->resp, &nb->resp_index);
    if (strcmp(cmd, "interfaces") == 0) {
	debug("interfaces");
        net_basic_handle_interfaces(nb);
    } else if (strcmp(cmd, "ifinfo") == 0) {
        char ifname[IFNAMSIZ];
        if (ei_decode_string(req, &req_index, ifname) < 0)
            errx(EXIT_FAILURE, "ifinfo requires ifname");
        debug("ifinfo: %s", ifname);

        net_basic_handle_ifinfo(nb, ifname);
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
