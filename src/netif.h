#ifndef NETIF_H
#define NETIF_H

#include <libmnl/libmnl.h>
#include "erlcmd.h"

struct netif {
    // NETLINK_ROUTE socket information
    struct mnl_socket *nl;
    int seq;

    // NETLINK_KOBJECT_UEVENT socket information
    struct mnl_socket *nl_uevent;

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

    // Async response handling
    void (*response_callback)(struct netif *nb, int bytecount);
    void (*response_error_callback)(struct netif *nb, int err);
    unsigned int response_portid;
    int response_seq;

    // Holder of the most recently encounted errno.
    int last_error;
};

#endif // NETIF_H
