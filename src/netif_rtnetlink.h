#ifndef NETIF_RTNETLINK_H
#define NETIF_RTNETLINK_H

struct netif;
struct nlmsghdr;

int netif_build_ifinfo(const struct nlmsghdr *nlh, void *data);
void handle_rtnetlink_notification(struct netif *nb, int bytecount);

#endif // NETIF_RTNETLINK_H
