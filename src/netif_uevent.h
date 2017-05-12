#ifndef NETIF_UEVENT_H
#define NETIF_UEVENT_H

struct netif;

void nl_uevent_process(struct netif *nb);

#endif // NETIF_UEVENT_H
