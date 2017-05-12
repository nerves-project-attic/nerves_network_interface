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

#include "netif_uevent.h"

#include "netif.h"
#include "util.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>

void nl_uevent_process(struct netif *nb)
{
    int bytecount = mnl_socket_recvfrom(nb->nl_uevent, nb->nlbuf, sizeof(nb->nlbuf));
    if (bytecount <= 0)
        err(EXIT_FAILURE, "mnl_socket_recvfrom");

    // uevent messages are concatenated strings
    enum hotplug_operation {
        HOTPLUG_OPERATION_NONE = 0,
        HOTPLUG_OPERATION_ADD,
        HOTPLUG_OPERATION_MOVE,
        HOTPLUG_OPERATION_REMOVE
    } operation = HOTPLUG_OPERATION_NONE;

    const char *str = nb->nlbuf;
    if (strncmp(str, "add@", 4) == 0)
        operation = HOTPLUG_OPERATION_ADD;
    else if (strncmp(str, "move@", 5) == 0)
        operation = HOTPLUG_OPERATION_MOVE;
    else if (strncmp(str, "remove@", 7) == 0)
        operation = HOTPLUG_OPERATION_REMOVE;
    else
        return; // Not interested in this message.

    const char *str_end = str + bytecount;
    str += strlen(str) + 1;

    // Extract the fields of interest
    const char *ifname = NULL;
    const char *subsystem = NULL;
    const char *ifindex = NULL;
    for (;str < str_end; str += strlen(str) + 1) {
        if (strncmp(str, "INTERFACE=", 10) == 0)
            ifname = str + 10;
        else if (strncmp(str, "SUBSYSTEM=", 10) == 0)
            subsystem = str + 10;
        else if (strncmp(str, "IFINDEX=", 8) == 0)
            ifindex = str + 8;
    }

    // Check that we have the required fields that this is a
    // "net" subsystem event. If yes, send the notification.
    if (ifname && subsystem && ifindex && strcmp(subsystem, "net") == 0) {
        nb->resp_index = sizeof(uint16_t); // Skip over payload size
        nb->resp[nb->resp_index++] = 'n';
        ei_encode_version(nb->resp, &nb->resp_index);

        ei_encode_tuple_header(nb->resp, &nb->resp_index, 2);

        switch (operation) {
        case HOTPLUG_OPERATION_ADD:
            ei_encode_atom(nb->resp, &nb->resp_index, "ifadded");
            break;
        case HOTPLUG_OPERATION_MOVE:
            ei_encode_atom(nb->resp, &nb->resp_index, "ifrenamed");
            break;
        case HOTPLUG_OPERATION_REMOVE:
        default: // Silence warning
            ei_encode_atom(nb->resp, &nb->resp_index, "ifremoved");
            break;
        }

        ei_encode_map_header(nb->resp, &nb->resp_index, 2);

        encode_kv_long(nb, "index", strtol(ifindex, NULL, 0));
        encode_kv_string(nb, "ifname", ifname);

        erlcmd_send(nb->resp, nb->resp_index);
    }
}
