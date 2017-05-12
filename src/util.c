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

#include "util.h"
#include "netif.h"

#include <string.h>
#include <ctype.h>

#include <arpa/inet.h>

int string_to_macaddr(const char *str, unsigned char *mac)
{
    if (sscanf(str,
               "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &mac[0], &mac[1], &mac[2],
               &mac[3], &mac[4], &mac[5]) != 6)
        return -1;
    else
        return 0;
}

int macaddr_to_string(const unsigned char *mac, char *str)
{
    snprintf(str, MACADDR_STR_LEN,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
    return 0;
}

void encode_kv_long(struct netif *nb, const char *key, long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_long(nb->resp, &nb->resp_index, value);
}

void encode_kv_ulong(struct netif *nb, const char *key, unsigned long value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_ulong(nb->resp, &nb->resp_index, value);
}
void encode_kv_bool(struct netif *nb, const char *key, int value)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_boolean(nb->resp, &nb->resp_index, value);
}
void encode_string(char *buf, int *index, const char *str)
{
    // Encode strings as binaries so that we get Elixir strings
    // NOTE: the strings that we encounter here are expected to be ASCII to
    //       my knowledge
    ei_encode_binary(buf, index, str, strlen(str));
}
void encode_kv_string(struct netif *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    encode_string(nb->resp, &nb->resp_index, str);
}
void encode_kv_atom(struct netif *nb, const char *key, const char *str)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);
    ei_encode_atom(nb->resp, &nb->resp_index, str);
}

void encode_kv_macaddr(struct netif *nb, const char *key, const unsigned char *macaddr)
{
    ei_encode_atom(nb->resp, &nb->resp_index, key);

    char macaddr_str[MACADDR_STR_LEN];

    // Only handle 6 byte mac addresses (to my knowledge, this is the only case)
    macaddr_to_string(macaddr, macaddr_str);

    encode_string(nb->resp, &nb->resp_index, macaddr_str);
}

/**
 * @brief Encode an IP address
 *
 * @param key the kv key part
 * @param af AF_INET or AF_INET6
 * @param addr the IP address in binary form
 */
void encode_kv_ipaddress(struct netif *nb, const char *key, int af, const void *addr)
{
    char addrstr[INET6_ADDRSTRLEN];
    if (inet_ntop(af, addr, addrstr, sizeof(addrstr))) {
        encode_kv_string(nb, key, addrstr);
    } else {
        debug("inet_ntop failed for '%s'? : %s", key, strerror(errno));
        encode_kv_string(nb, key, "");
    }
}

#ifdef DEBUG
void fprintf_nested(FILE *fd, const struct nlattr *attr)
{
    int rem = 0;
    unsigned int i;


    for (i=0; i< mnl_attr_get_payload_len(attr); i+=4) {
        char *b = (char *) mnl_attr_get_payload(attr);
        const struct nlattr *subattr = (const struct nlattr *) (b+i);

        if (rem == 0 && (subattr->nla_type & NLA_TYPE_MASK) != 0) {
            fprintf(fd, "|%c[%d;%dm"
                        "%.5u"
                        "%c[%dm"
                        "|"
                        "%c[%d;%dm"
                        "%c%c"
                        "%c[%dm"
                        "|"
                        "%c[%d;%dm"
                        "%.5u"
                        "%c[%dm|\t",
                    27, 1, 31,
                    subattr->nla_len,
                    27, 0,
                    27, 1, 32,
                    subattr->nla_type & NLA_F_NESTED ? 'N' : '-',
                    subattr->nla_type &
                    NLA_F_NET_BYTEORDER ? 'B' : '-',
                    27, 0,
                    27, 1, 34,
                    subattr->nla_type & NLA_TYPE_MASK,
                    27, 0);
            fprintf(fd, "|len |flags| type|\n");

            if (!(subattr->nla_type & NLA_F_NESTED)) {
                rem = NLA_ALIGN(subattr->nla_len) -
                        sizeof(struct nlattr);
            }
            /* this is the attribute payload. */
        } else if (rem > 0) {
            rem -= 4;
            fprintf(fd, "| %.2x %.2x %.2x %.2x  |\t",
                    0xff & b[i],    0xff & b[i+1],
                    0xff & b[i+2],  0xff & b[i+3]);
            fprintf(fd, "|      data      |");
            fprintf(fd, "\t %c %c %c %c\n",
                    isprint(b[i]) ? b[i] : ' ',
                    isprint(b[i+1]) ? b[i+1] : ' ',
                isprint(b[i+2]) ? b[i+2] : ' ',
                isprint(b[i+3]) ? b[i+3] : ' ');
        }
    }
    fprintf(fd, "----------------\t------------------\n");
}
#endif
