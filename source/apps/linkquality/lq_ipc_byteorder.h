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

#ifndef LQ_IPC_BYTEORDER_H
#define LQ_IPC_BYTEORDER_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include "wifi_base.h"
#include "lq_ipc_sender.h"

// Host byte order detection
static inline const char *lq_detect_host_byteorder(void)
{
    uint32_t val = 0x01020304;
    uint8_t *p = (uint8_t *)&val;
    if (p[0] == 0x01) return "big-endian";
    if (p[0] == 0x04) return "little-endian";
    return "unknown";
}

// Signed field helpers (reinterpret through unsigned)
static inline uint32_t lq_hton_i32(int32_t val)
{
    uint32_t u;
    memcpy(&u, &val, sizeof(u));
    return htobe32(u);
}

static inline int32_t lq_ntoh_i32(uint32_t net)
{
    uint32_t host = be32toh(net);
    int32_t val;
    memcpy(&val, &host, sizeof(val));
    return val;
}

static inline uint64_t lq_hton_i64(int64_t val)
{
    uint64_t u;
    memcpy(&u, &val, sizeof(u));
    return htobe64(u);
}

static inline int64_t lq_ntoh_i64(uint64_t net)
{
    uint64_t host = be64toh(net);
    int64_t val;
    memcpy(&val, &host, sizeof(val));
    return val;
}

// Convert lq_ipc_header_t to/from network byte order
static inline void lq_hdr_hton(lq_ipc_header_t *hdr)
{
    hdr->msg_type    = htobe32(hdr->msg_type);
    hdr->num_entries = htobe32(hdr->num_entries);
}

static inline void lq_hdr_ntoh(lq_ipc_header_t *hdr)
{
    hdr->msg_type    = be32toh(hdr->msg_type);
    hdr->num_entries = be32toh(hdr->num_entries);
}

// Convert timestamp_t to/from network byte order
static inline void lq_timestamp_hton(timestamp_t *ts)
{
    uint64_t sec_net  = lq_hton_i64(ts->tv_sec);
    uint32_t nsec_net = lq_hton_i32(ts->tv_nsec);
    memcpy(&ts->tv_sec, &sec_net, sizeof(ts->tv_sec));
    memcpy(&ts->tv_nsec, &nsec_net, sizeof(ts->tv_nsec));
}

static inline void lq_timestamp_ntoh(timestamp_t *ts)
{
    uint64_t sec_net;
    uint32_t nsec_net;
    memcpy(&sec_net, &ts->tv_sec, sizeof(sec_net));
    memcpy(&nsec_net, &ts->tv_nsec, sizeof(nsec_net));
    ts->tv_sec  = lq_ntoh_i64(sec_net);
    ts->tv_nsec = lq_ntoh_i32(nsec_net);
}

// Convert dev_stats_t to/from network byte order
static inline void lq_dev_stats_hton(dev_stats_t *d)
{
    d->cli_PacketsSent        = htobe32(d->cli_PacketsSent);
    d->cli_PacketsReceived    = htobe32(d->cli_PacketsReceived);
    d->cli_RetransCount       = htobe32(d->cli_RetransCount);
    d->cli_RxRetries          = htobe64(d->cli_RxRetries);
    d->cli_SNR                = (int32_t)lq_hton_i32(d->cli_SNR);
    d->cli_MaxDownlinkRate    = htobe32(d->cli_MaxDownlinkRate);
    d->cli_MaxUplinkRate      = htobe32(d->cli_MaxUplinkRate);
    d->cli_LastDataDownlinkRate = htobe32(d->cli_LastDataDownlinkRate);
    d->cli_LastDataUplinkRate = htobe32(d->cli_LastDataUplinkRate);
    /* cli_PowerSaveMode is uint8_t — no conversion needed */
}

static inline void lq_dev_stats_ntoh(dev_stats_t *d)
{
    d->cli_PacketsSent        = be32toh(d->cli_PacketsSent);
    d->cli_PacketsReceived    = be32toh(d->cli_PacketsReceived);
    d->cli_RetransCount       = be32toh(d->cli_RetransCount);
    d->cli_RxRetries          = be64toh(d->cli_RxRetries);
    d->cli_SNR                = lq_ntoh_i32((uint32_t)d->cli_SNR);
    d->cli_MaxDownlinkRate    = be32toh(d->cli_MaxDownlinkRate);
    d->cli_MaxUplinkRate      = be32toh(d->cli_MaxUplinkRate);
    d->cli_LastDataDownlinkRate = be32toh(d->cli_LastDataDownlinkRate);
    d->cli_LastDataUplinkRate = be32toh(d->cli_LastDataUplinkRate);
    /* cli_PowerSaveMode is uint8_t — no conversion needed */
}

//Convert stats_arg_t to/from network byte order
static inline void lq_stats_arg_hton(stats_arg_t *s)
{
    /* mac_str, ap_mac_str: char arrays — no conversion */
    /* vap_index, radio_index: uint8_t — no conversion */
    s->channel_utilization = (int32_t)lq_hton_i32(s->channel_utilization);
    lq_dev_stats_hton(&s->dev);
    lq_timestamp_hton(&s->total_connected_time);
    lq_timestamp_hton(&s->total_disconnected_time);
    s->event       = (int32_t)lq_hton_i32(s->event);
    s->status_code = htobe16(s->status_code);
    /* dhcp_event, dhcp_msg_type: uint8_t — no conversion */
}

static inline void lq_stats_arg_ntoh(stats_arg_t *s)
{
    /* mac_str, ap_mac_str: char arrays — no conversion */
    /* vap_index, radio_index: uint8_t — no conversion */
    s->channel_utilization = lq_ntoh_i32((uint32_t)s->channel_utilization);
    lq_dev_stats_ntoh(&s->dev);
    lq_timestamp_ntoh(&s->total_connected_time);
    lq_timestamp_ntoh(&s->total_disconnected_time);
    s->event       = lq_ntoh_i32((uint32_t)s->event);
    s->status_code = be16toh(s->status_code);
    /* dhcp_event, dhcp_msg_type: uint8_t — no conversion */
}

// Convert an array of stats_arg_t to/from network byte order
static inline void lq_stats_arg_array_hton(stats_arg_t *arr, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        lq_stats_arg_hton(&arr[i]);
    }
}

static inline void lq_stats_arg_array_ntoh(stats_arg_t *arr, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        lq_stats_arg_ntoh(&arr[i]);
    }
}
#endif // LQ_IPC_BYTEORDER_H
