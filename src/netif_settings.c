#include "netif.h"
#include "netif_routing.h"
#include "netif_settings.h"
#include "util.h"
#include "erlcmd.h"

#include <arpa/inet.h>
#include <err.h>
#include <linux/if.h>
#include <string.h>
#include <sys/ioctl.h>

static int prep_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);
static int prep_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, void **context);
static int set_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context);
static int get_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname);

// These handlers are listed in the order that they should be invoked when
// configuring the interface. For example, "ipv4_gateway" is listed at the end
// so that it is set after the address and subnet_mask. If this is not done,
// setting the gateway may fail since Linux thinks that it is on the wrong subnet.
const struct ip_setting_handler handlers[] = {
    { "ipv4_address", prep_ipaddr_ioctl, set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFADDR, SIOCGIFADDR },
    { "ipv4_subnet_mask", prep_ipaddr_ioctl, set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFNETMASK, SIOCGIFNETMASK },
    { "ipv4_broadcast", prep_ipaddr_ioctl, set_ipaddr_ioctl, get_ipaddr_ioctl, SIOCSIFBRDADDR, SIOCGIFBRDADDR },
    { "ipv4_gateway", prep_default_gateway, set_default_gateway, get_default_gateway, 0, 0 },
    { "mac_address", prep_mac_address_ioctl, set_mac_address_ioctl, get_mac_address_ioctl, SIOCSIFHWADDR, SIOCGIFHWADDR },
    { NULL, NULL, NULL, NULL, 0, 0}
};
#define HANDLER_COUNT (sizeof(handlers) / sizeof(handlers[0]))

size_t ip_setting_count()
{
    return HANDLER_COUNT;
}

static int prep_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char macaddr_str[MACADDR_STR_LEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, macaddr_str, sizeof(macaddr_str)) < 0)
        errx(EXIT_FAILURE, "mac address parameter required for '%s'", handler->name);

    // Be forgiving and if the user specifies an empty IP address, just skip
    // this request.
    if (macaddr_str[0] == '\0')
        *context = NULL;
    else
        *context = strdup(macaddr_str);

    return 0;
}


static int set_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    const char *macaddr_str = (const char *) context;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_family = AF_UNIX;
    unsigned char *mac = (unsigned char *) &ifr.ifr_hwaddr.sa_data;
    if (string_to_macaddr(macaddr_str, mac) < 0) {
        debug("Bad MAC address for '%s': %s", handler->name, macaddr_str);
        nb->last_error = EINVAL;
        return -1;
    }

    if (ioctl(nb->inet_fd, handler->ioctl_set, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

static int get_mac_address_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, handler->ioctl_get, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for getting '%s': %s", handler->ioctl_get, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (addr->sin_family == AF_UNIX) {
        encode_kv_macaddr(nb, handler->name, (unsigned char *) &ifr.ifr_hwaddr.sa_data);
    } else {
        debug("got unexpected sin_family %d for '%s'", addr->sin_family, handler->name);
        nb->last_error = EINVAL;
        return -1;
    }
    return 0;
}

static int prep_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char ipaddr[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, ipaddr, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    // Be forgiving and if the user specifies an empty IP address, just skip
    // this request.
    if (ipaddr[0] == '\0')
        *context = NULL;
    else
        *context = strdup(ipaddr);

    return 0;
}

static int set_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    const char *ipaddr = (const char *) context;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, ipaddr, &addr->sin_addr) <= 0) {
        debug("Bad IP address for '%s': %s", handler->name, ipaddr);
        nb->last_error = EINVAL;
        return -1;
    }

    if (ioctl(nb->inet_fd, handler->ioctl_set, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for setting '%s': %s", handler->ioctl_set, handler->name, strerror(errno));
        nb->last_error = errno;
        return -1;
    }

    return 0;
}

static int get_ipaddr_ioctl(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, handler->ioctl_get, &ifr) < 0) {
        debug("ioctl(0x%04x) failed for getting '%s': %s. Skipping...", handler->ioctl_get, handler->name, strerror(errno));
        encode_kv_string(nb, handler->name, "");
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_addr;
    if (addr->sin_family == AF_INET) {
        char addrstr[INET_ADDRSTRLEN];
        if (!inet_ntop(addr->sin_family, &addr->sin_addr, addrstr, sizeof(addrstr))) {
            debug("inet_ntop failed for '%s'? : %s", handler->name, strerror(errno));
            nb->last_error = errno;
            return -1;
        }
        encode_kv_string(nb, handler->name, addrstr);
    } else {
        debug("got unexpected sin_family %d for '%s'", addr->sin_family, handler->name);
        nb->last_error = EINVAL;
        return -1;
    }
    return 0;
}

static int prep_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, void **context)
{
    char gateway[INET_ADDRSTRLEN];
    if (erlcmd_decode_string(nb->req, &nb->req_index, gateway, INET_ADDRSTRLEN) < 0)
        errx(EXIT_FAILURE, "ip address parameter required for '%s'", handler->name);

    *context = strdup(gateway);
    return 0;
}

static int set_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname, void *context)
{
    (void) handler;
    const char *gateway = context;

    // Before one can be set, any configured gateways need to be removed.
    if (remove_all_gateways(nb, ifname) < 0)
        return -1;

    // If no gateway was specified, then we're done.
    if (*gateway == '\0')
        return 0;

    return add_default_gateway(nb, ifname, gateway);
}

static int ifname_to_index(struct netif *nb, const char *ifname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(nb->inet_fd, SIOCGIFINDEX, &ifr) < 0) {
        nb->last_error = errno;
        return -1;
    }
    return ifr.ifr_ifindex;
}

static int get_default_gateway(const struct ip_setting_handler *handler, struct netif *nb, const char *ifname)
{
    int oif = ifname_to_index(nb, ifname);
    if (oif < 0)
        return -1;

    char gateway_ip[INET_ADDRSTRLEN];
    find_default_gateway(nb, oif, gateway_ip);

    // If the gateway isn't found, then the empty string is what we want.
    encode_kv_string(nb, handler->name, gateway_ip);
    return 0;
}
