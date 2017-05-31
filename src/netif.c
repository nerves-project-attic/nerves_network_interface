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

#include "netif.h"
#include "netif_rtnetlink.h"
#include "netif_settings.h"
#include "util.h"

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static void netif_init(struct netif *nb)
{
    memset(nb, 0, sizeof(*nb));
    nb->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nb->nl)
        err(EXIT_FAILURE, "mnl_socket_open (NETLINK_ROUTE)");

    if (mnl_socket_bind(nb->nl, RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, MNL_SOCKET_AUTOPID) < 0)
        err(EXIT_FAILURE, "mnl_socket_bind");

    nb->nl_uevent = mnl_socket_open(NETLINK_KOBJECT_UEVENT);
    if (!nb->nl_uevent)
        err(EXIT_FAILURE, "mnl_socket_open (NETLINK_KOBJECT_UEVENT)");

    nb->inet_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nb->inet_fd < 0)
        err(EXIT_FAILURE, "socket");

    nb->seq = 1;
}

static void netif_cleanup(struct netif *nb)
{
    mnl_socket_close(nb->nl);
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
    erlcmd_send(nb->resp, nb->resp_index);
    nb->resp_index = 0;
}

static void rtnetlink_dump_links(struct netif *nb)
{
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;

    nlh = mnl_nlmsg_put_header(nb->nlbuf);
    nlh->nlmsg_type	= RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = nb->seq++;

    ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = ARPHRD_ETHER;
    ifi->ifi_index = 0;
    ifi->ifi_flags = 0;
    ifi->ifi_change = 0xffffffff;

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0) {
        if (errno == EBUSY)
            nb->dump_interfaces = true;
        else
            err(EXIT_FAILURE, "mnl_socket_send(rtnetlink_dump_links)");
    }
}

static void rtnetlink_dump_addrs(struct netif *nb, unsigned char family)
{
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;

    nlh = mnl_nlmsg_put_header(nb->nlbuf);
    nlh->nlmsg_type	= RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = nb->seq++;
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = family; ;

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0) {
        if (errno == EBUSY) {
            if (family == AF_INET)
                nb->dump_addresses = true;
            else
                nb->dump_addresses6 = true;
        } else
            err(EXIT_FAILURE, "mnl_socket_send(rtnetlink_dump_addrs)");
    }
}

static void rtnetlink_dump_routes(struct netif *nb, unsigned char family)
{
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;

    nlh = mnl_nlmsg_put_header(nb->nlbuf);
    nlh->nlmsg_type	= RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = nb->seq++;
    rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rtm->rtm_family = family; ;

    if (mnl_socket_sendto(nb->nl, nlh, nlh->nlmsg_len) < 0) {
        if (errno == EBUSY) {
            if (family == AF_INET)
                nb->dump_routes = true;
            else
                nb->dump_routes6 = true;
        } else
            err(EXIT_FAILURE, "mnl_socket_send(rtnetlink_dump_routes)");
    }
}

static void netif_handle_refresh(struct netif *nb)
{
    // On a refresh, send requests to rtnetlink to dump everything.
    // Since the commands can't go out all at once, start dumping links
    // and then dump everything else.
    rtnetlink_dump_links(nb);

    nb->dump_addresses = true;
    nb->dump_addresses6 = true;
    nb->dump_routes = true;
    nb->dump_routes6 = true;

    start_response(nb);
    ei_encode_atom(nb->resp, &nb->resp_index, "ok");
    send_response(nb);
}

static void nl_route_process(struct netif *nb)
{
    int bytecount = mnl_socket_recvfrom(nb->nl, nb->nlbuf, sizeof(nb->nlbuf));
    if (bytecount <= 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    int rc = handle_rtnetlink_notification(nb, bytecount);

    if (rc == MNL_CB_STOP) {
        // MNL_CB_STOP is notified at the end of each dump... call
        if (nb->dump_interfaces) {
            nb->dump_interfaces = false;
            rtnetlink_dump_links(nb);
        } else if (nb->dump_addresses) {
            nb->dump_addresses = false;
            rtnetlink_dump_addrs(nb, AF_INET);
        } else if (nb->dump_addresses6) {
            nb->dump_addresses6 = false;
            rtnetlink_dump_addrs(nb, AF_INET6);
        } else if (nb->dump_routes) {
            nb->dump_routes = false;
            rtnetlink_dump_routes(nb, AF_INET);
        } else if (nb->dump_routes6) {
            nb->dump_routes6 = false;
            rtnetlink_dump_routes(nb, AF_INET6);
        }
    }
}

static void netif_handle_send(struct netif *nb)
{
    send_rtnetlink_message(nb);

    start_response(nb);
    ei_encode_atom(nb->resp, &nb->resp_index, "ok");
    send_response(nb);
}

static void netif_request_handler(const char *req, void *cookie)
{
    struct netif *nb = (struct netif *) cookie;

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

    if (strcmp(cmd, "refresh") == 0) {
        netif_handle_refresh(nb);
    } else if (strcmp(cmd, "send") == 0) {
        netif_handle_send(nb);
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
            nl_route_process(&nb);
    }

    netif_cleanup(&nb);
    return 0;
}
