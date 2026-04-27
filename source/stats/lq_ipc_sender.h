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

#ifndef LQ_IPC_SENDER_H
#define LQ_IPC_SENDER_H

#include <stdint.h>

/*
 * AF_UNIX datagram socket path shared between OneWifi (sender) and
 * linkquality-stats daemon (receiver).
 */
#define LQ_STATS_SOCKET_PATH "/tmp/linkquality_stats.sock"

/*
 * IPC message types — one per distinct event class from
 * wifi_stats_assoc_client.c call sites.
 */
#define LQ_IPC_MSG_PERIODIC_STATS    1   /* Call Site 1: periodic stats batch    */
#define LQ_IPC_MSG_DISCONNECT        2   /* Call Sites 2,4: station disconnect   */
#define LQ_IPC_MSG_RAPID_DISCONNECT  3   /* Call Site 3: rapid disconnect detect */

/*
 * Fixed-size header prepended to every datagram.
 * Followed by num_entries × lq_ipc_sta_entry_t.
 */
typedef struct {
    uint32_t msg_type;       /* LQ_IPC_MSG_* */
    uint32_t num_entries;    /* number of station entries that follow */
} lq_ipc_header_t;

/*
 * Per-station payload transmitted over the socket.
 * Kept minimal — just the MAC string for the initial implementation.
 */
typedef struct {
    char mac_str[18];        /* "aa:bb:cc:dd:ee:ff\0" */
} lq_ipc_sta_entry_t;

/*
 * Send a link-quality event over the AF_UNIX datagram socket.
 *
 *   msg_type  – LQ_IPC_MSG_PERIODIC_STATS / _DISCONNECT / _RAPID_DISCONNECT
 *   macs      – array of MAC address strings (each 18 bytes including NUL)
 *   count     – number of entries in `macs`
 *
 * Returns 0 on success, -1 on error (non-fatal — logged and ignored).
 */
int lq_ipc_send(uint32_t msg_type, const char macs[][18], uint32_t count);

#endif /* LQ_IPC_SENDER_H */
