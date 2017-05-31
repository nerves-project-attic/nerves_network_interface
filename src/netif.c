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
    debug("sending response: %d bytes", nb->resp_index);
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


static void netif_handle_get(struct netif *nb,
                                 const char *ifname)
{
    start_response(nb);
    int original_resp_index = nb->resp_index;

    size_t num_entries = ip_setting_count();

    ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);
    ei_encode_atom(nb->resp, &nb->resp_index, "ok");
    ei_encode_map_header(nb->resp, &nb->resp_index, num_entries);

    nb->last_error = 0;
    for (size_t i = 0; i < num_entries; i++) {
        const struct ip_setting_handler *handler = &handlers[i];
        if (handler->get(handler, nb, ifname) < 0)
            break;
    }

    if (nb->last_error) {
        nb->resp_index = original_resp_index;
        erlcmd_encode_errno_error(nb->resp, &nb->resp_index, nb->last_error);
    }
    send_response(nb);
}

static const struct ip_setting_handler *find_handler(const char *name)
{
    for (const struct ip_setting_handler *handler = handlers;
         handler->name != NULL;
         handler++) {
        if (strcmp(handler->name, name) == 0)
            return handler;
    }
    return NULL;
}

static void netif_handle_set(struct netif *nb,
                             const char *ifname)
{
    nb->last_error = 0;

    start_response(nb);

    int arity;
    if (ei_decode_map_header(nb->req, &nb->req_index, &arity) < 0)
        errx(EXIT_FAILURE, "setting attributes requires a map");

    size_t num_entries = ip_setting_count();
    void *handler_context[num_entries];
    memset(handler_context, 0, sizeof(handler_context));

    // Parse all options
    for (int i = 0; i < arity && nb->last_error == 0; i++) {
        char name[32];
        if (erlcmd_decode_atom(nb->req, &nb->req_index, name, sizeof(name)) < 0)
            errx(EXIT_FAILURE, "error in map encoding");

        // Look up the option. If we don't know it, silently ignore it so that
        // the caller can pass in maps that contain options for other code.
        const struct ip_setting_handler *handler = find_handler(name);
        if (handler)
            handler->prep(handler, nb, &handler_context[handler - handlers]);
        else
            ei_skip_term(nb->req, &nb->req_index);
    }

    // If no errors, then set everything
    if (!nb->last_error) {
        // Order is important: see note on handlers
        for (size_t i = 0; i < num_entries; i++) {
            if (handler_context[i]) {
                handlers[i].set(&handlers[i], nb, ifname, handler_context[i]);
                free(handler_context[i]);
            }
        }
    }

    // Encode and send the response
    if (nb->last_error)
        erlcmd_encode_errno_error(nb->resp, &nb->resp_index, nb->last_error);
    else
        erlcmd_encode_ok(nb->resp, &nb->resp_index);

    send_response(nb);
}

static void netif_handle_send(struct netif *nb)
{
    send_rtnetlink_message(nb);
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

    if (strcmp(cmd, "refresh") == 0) {
        debug("refresh");
        netif_handle_refresh(nb);
    } else if (strcmp(cmd, "send") == 0) {
        debug("send");
        netif_handle_send(nb);
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
                erlcmd_decode_string(nb->req, &nb->req_index, ifname, IFNAMSIZ) < 0)
            errx(EXIT_FAILURE, "setup requires {ifname, parameters}");
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
