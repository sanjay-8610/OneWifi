/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "lq_ipc_sender.h"
#include "wifi_util.h"

static int lq_ipc_fd = -1;

int lq_ipc_send(uint32_t msg_type, const char macs[][18], uint32_t count)
{
    if (count == 0 || macs == NULL) {
        return -1;
    }

    if (lq_ipc_fd < 0) {
        lq_ipc_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (lq_ipc_fd < 0) {
            wifi_util_error_print(WIFI_MON,
                "%s:%d socket() failed: %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LQ_STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    size_t payload_sz = sizeof(lq_ipc_header_t) + count * sizeof(lq_ipc_sta_entry_t);
    uint8_t *buf = malloc(payload_sz);
    if (!buf) {
        wifi_util_error_print(WIFI_MON,
            "%s:%d malloc(%zu) failed\n", __func__, __LINE__, payload_sz);
        return -1;
    }

    lq_ipc_header_t *hdr = (lq_ipc_header_t *)buf;
    hdr->msg_type    = msg_type;
    hdr->num_entries = count;

    lq_ipc_sta_entry_t *entries = (lq_ipc_sta_entry_t *)(buf + sizeof(lq_ipc_header_t));
    for (uint32_t i = 0; i < count; i++) {
        memset(&entries[i], 0, sizeof(lq_ipc_sta_entry_t));
        strncpy(entries[i].mac_str, macs[i], sizeof(entries[i].mac_str) - 1);
    }

    ssize_t ret = sendto(lq_ipc_fd, buf, payload_sz, MSG_DONTWAIT,
                         (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        wifi_util_dbg_print(WIFI_MON,
            "%s:%d sendto(%s) failed: %s (non-fatal)\n",
            __func__, __LINE__, LQ_STATS_SOCKET_PATH, strerror(errno));
    }

    free(buf);
    return (ret < 0) ? -1 : 0;
}
