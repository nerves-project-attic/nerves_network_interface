#ifndef NETIF_SETTINGS_H
#define NETIF_SETTINGS_H

#include <stdlib.h>

struct netif;

struct ip_setting_handler {
    const char *name;
    int (*prep)(const struct ip_setting_handler *handler, struct netif *nb, void **context);
    int (*set)(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
    int (*get)(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);

    // data for handlers
    int ioctl_set;
    int ioctl_get;
};

extern const struct ip_setting_handler handlers[];
size_t ip_setting_count();

#endif // NETIF_SETTINGS_H
