#ifndef NETIF_RTNETLINK_H
#define NETIF_RTNETLINK_H

struct netif;
struct nlmsghdr;

void handle_rtnetlink_notification(struct netif *nb, int bytecount);

#endif // NETIF_RTNETLINK_H
