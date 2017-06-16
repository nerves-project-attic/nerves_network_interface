#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

#define DEBUG
#ifdef DEBUG
#define debug(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\r\n"); } while(0)
#else
#define debug(...)
#endif

// MAC address utilities
#define MACADDR_STR_LEN      18 // aa:bb:cc:dd:ee:ff and a null terminator

int string_to_macaddr(const char *str, unsigned char *mac);
int macaddr_to_string(const unsigned char *mac, char *str);

// Encoding
struct netif;
void encode_kv_long(struct netif *nb, const char *key, long value);
void encode_kv_ulong(struct netif *nb, const char *key, unsigned long value);
void encode_kv_bool(struct netif *nb, const char *key, int value);
void encode_string(char *buf, int *index, const char *str);
void encode_kv_string(struct netif *nb, const char *key, const char *str);
void encode_kv_binary(struct netif *nb, const char *key, const void *buffer, size_t len);
void encode_kv_atom(struct netif *nb, const char *key, const char *str);
void encode_kv_macaddr(struct netif *nb, const char *key, const unsigned char *macaddr);
void encode_kv_ipaddress(struct netif *nb, const char *key, int af, const void *addr);

#endif // UTIL_H
