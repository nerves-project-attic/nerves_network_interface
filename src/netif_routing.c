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

#include "netif_routing.h"
#include <net/route.h>
#include <libmnl/libmnl.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

#include "netif.h"
#include "util.h"

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

int check_default_gateway(const struct nlmsghdr *nlh, void *data)
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

void find_default_gateway(struct netif *nb,
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

int remove_all_gateways(struct netif *nb, const char *ifname)
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

int add_default_gateway(struct netif *nb, const char *ifname, const char *gateway_ip)
{
    struct rtentry route;
    memset(&route, 0, sizeof(route));

    struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, gateway_ip, &addr->sin_addr) <= 0) {
        debug("Bad IP address for the default gateway: %s", gateway_ip);
        nb->last_error = EINVAL;
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
        nb->last_error = errno;
        return -1;
    }
    return 0;
}
