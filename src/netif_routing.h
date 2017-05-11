#ifndef NETIF_ROUTING_H
#define NETIF_ROUTING_H

struct nlmsghdr;
struct netif;

int check_default_gateway(const struct nlmsghdr *nlh, void *data);
void find_default_gateway(struct netif *nb,
                                int oif,
                                char *result);
int remove_all_gateways(struct netif *nb, const char *ifname);
int add_default_gateway(struct netif *nb, const char *ifname, const char *gateway_ip);

#endif // NETIF_ROUTING_H
