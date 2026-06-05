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
#include <stddef.h>

/*
 * AF_UNIX datagram socket path shared between OneWifi (sender) and
 * linkquality-stats daemon (receiver).
 */
#define LQ_STATS_SOCKET_PATH "/tmp/linkquality_stats.sock"
#define LQ_ONEWIFI_SOCKET_PATH "/tmp/linkquality_onewifi.sock"  /* WEI → OneWifi */

/*
 * IPC message types — each maps to a qmgr function in linkquality-stats.
 *
 * PERIODIC_STATS   → add_stats_metrics() + periodic_caffinity_stats_update()
 * DISCONNECT       → remove_link_stats()
 * RAPID_DISCONNECT → disconnect_link_stats()
 * CAFFINITY_EVENT  → unified frame event (HAL/DHCP/probe/auth/assoc); frame_type
 *                     in stats_arg_t selects WEI handling path
 * START_METRICS    → start_link_metrics() + set_max_snr_radios()
 * STOP_METRICS     → stop_link_metrics()
 * REGISTER_STA     → register_station_mac() [ignite]
 * UNREGISTER_STA   → unregister_station_mac() [ignite]
 * REINIT_METRICS   → reinit_link_metrics() [server_arg_t payload]
 * SET_MAX_SNR      → set_max_snr_radios() [radio_max_snr_t payload]
 * ASSOC_REQ_DATA   → update caffinity with assoc request IEs [stats_arg_t payload]
 */
#define LQ_IPC_MSG_PERIODIC_STATS    1
#define LQ_IPC_MSG_DISCONNECT        2
#define LQ_IPC_MSG_RAPID_DISCONNECT  3
#define LQ_IPC_MSG_CAFFINITY_EVENT   4
#define LQ_IPC_MSG_START_METRICS     5
#define LQ_IPC_MSG_STOP_METRICS      6
#define LQ_IPC_MSG_REGISTER_STA      7
#define LQ_IPC_MSG_UNREGISTER_STA    8
#define LQ_IPC_MSG_REINIT_METRICS    9
#define LQ_IPC_MSG_SET_MAX_SNR      10
#define LQ_IPC_MSG_SET_SCORE_PARAMS 11
#define LQ_IPC_MSG_ASSOC_REQ_DATA   12  /* OneWifi → WEI: assoc req IEs on success (stats_arg_t) */
#define LQ_IPC_MSG_DISCONNECT_CLIENTS_COUNT 13  /* WEI → OneWifi: disconnected client count */

/* IE IDs used in TLV encoding */
#define LQ_IE_ID_SSID            0
#define LQ_IE_ID_SUPPORTED_RATES 1
#define LQ_IE_ID_VENDOR_SPECIFIC 221

/*
 * Frame type identifiers stored in stats_arg_t.frame_type.
 * LQ_FRAME_TYPE_NONE (0) = DHCP / periodic update, no 802.11 frame.
 * Non-zero values carry a real 802.11 frame and trigger correlation on WEI.
 */
#define LQ_FRAME_TYPE_NONE   0
#define LQ_FRAME_TYPE_PROBE  1
#define LQ_FRAME_TYPE_AUTH   2
#define LQ_FRAME_TYPE_ASSOC  3

/*
 * Payload for LQ_IPC_MSG_DISCONNECT_CLIENTS_COUNT (WEI → OneWifi).
 * Sent when the number of disconnected clients changes.
 */
typedef struct {
    uint8_t count;  /* Number of currently disconnected clients */
} lq_disconnect_count_t;

/*
 * LQ TLV — the entire datagram is a single TLV, no wrapper header.
 *
 *   type  – LQ_IPC_MSG_* (1–10); uint8_t is sufficient
 *   len   – payload byte count; uint16_t covers all realistic payloads
 *   value – raw payload bytes (stats_arg_t[], server_arg_t, MAC string, etc.)
 *
 * Total header: 3 bytes (packed). AF_UNIX SOCK_DGRAM preserves exact datagram
 * boundaries. The receiver derives element count from len / sizeof(element_type).
 */
typedef struct {
    uint8_t  type;
    uint16_t len;
    uint8_t  value[];
} __attribute__((__packed__)) lq_tlv_t;

/*
 * Send a link-quality event over the AF_UNIX datagram socket.
 *
 *   msg_type   – LQ_IPC_MSG_*
 *   entries    – pointer to count × entry_size bytes (stats_arg_t array, etc.)
 *   count      – number of entries (0 for payload-less messages)
 *   entry_size – sizeof one entry
 *
 * Returns 0 on success, -1 on error (non-fatal — logged and ignored by caller).
 */
int lq_ipc_send(uint32_t msg_type, const void *entries,
                uint32_t count, size_t entry_size);

#endif /* LQ_IPC_SENDER_H */
