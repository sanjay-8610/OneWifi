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

#ifndef WIFI_LINKQUALITY_H
#define WIFI_LINKQUALITY_H

#ifdef __cplusplus
extern "C" {
#endif
#include <pthread.h>
#include "run_qmgr.h"
#include "wifi_base.h"
#include "wifi_webconfig.h"
#include "wifi_hal.h"
#include "wifi_linkquality_libs.h"

#define MAX_STR_LEN_LQ 128
#define MAX_BUFF_LEN 1048
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5
#define MAX_LQ_PROBE_ENTRIES 100
#define MAX_LQ_CONNECTED_STA_ENTRIES 10
#define LQ_CORRELATION_THRESHOLD 80
#define LQ_MEDIUM_CORR_THRESHOLD 70

/* Per-parameter comparison thresholds */
#define LQ_RSSI_THRESHOLD_DB      10     /* Allowed RSSI difference (dB) */
#define LQ_TIMESTAMP_THRESHOLD_MS 2000   /* Allowed timestamp difference (ms) */
#define LQ_SEQNUM_THRESHOLD       100    /* Allowed sequence-number difference */
#define LQ_SEQNUM_MAX             4096   /* 802.11 sequence number wraps at 4095 */

/* Weight (%) contributed by each validated parameter to the final score */
#define LQ_PARAM_WEIGHT           10

#define BUFFER_SIZE 65536
#define DHCP_BOOTP 1
#define DHCP_OPTION_PAD 0           // DHCP option padding
#define DHCP_OPTION_END 255         // DHCP option end marker
#define DHCP_OPTION_HOSTNAME 12
#define DHCP_OP_MSG_TYPE 53         // DHCP message type option
#define DHCP_OPTION_VENDOR_CLASS_ID 60

struct dhcp_data
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;

    uint32_t xid;

    uint16_t secs;
    uint16_t flags;

    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;

    uint8_t chaddr[16];
};

// Global socket + interface index
extern int dhcp_sniffer_fd;
extern int dhcp_sniffer_ifindex;

#define MAC_ADDRESS_LEN 6
typedef struct {
    double last_score;
    double last_threshold;
    int score_log_timer_id;
    int last_service_state;
    int iteration_count;
} ignite_lq_state_t;

typedef struct {
    mac_addr_str_t mac_str;
    frame_data_t msg_data;
    struct timespec timestamp;  /* Capture time (CLOCK_REALTIME, ns precision) */
    int ap_index;               /* VAP index where probe was received */
} lq_probe_req_elem_t;

typedef struct {
    mac_addr_str_t mac_str;
    frame_data_t msg_data;
    struct timespec timestamp;  /* Capture time (CLOCK_REALTIME, ns precision) */
    int ap_index;
    int sig_dbm;
    int sub_event; /* wifi_event_hal_assoc_req_frame or wifi_event_hal_reassoc_req_frame */
    mac_addr_str_t probe_mac; /* Probe-req MAC correlated at medium confidence (70-80%) */
} lq_connected_sta_elem_t;

typedef struct {
    stats_arg_t stats;
    server_arg_t server_arg;
    int size;
    ignite_lq_state_t ignite;
    hash_map_t *probe_req_map;
    pthread_mutex_t probe_map_lock;
    hash_map_t *connected_sta_map;
    pthread_mutex_t connected_sta_lock;
    int wei_recv_sock;             /* Socket to receive WEI → OneWifi messages */
    uint8_t disconnect_count;      /* Last known disconnected client count from WEI */
    bool send_probe_auth_assoc;    /* Flag: send probe/auth/assoc data when true */
} linkquality_data_t;

typedef uint8_t mac_address_t[MAC_ADDRESS_LEN];

#define CTRL_CAP_SZ 8

#if 0
typedef struct {
    void *data;
} multiap_data_t;


typedef enum {
    multiap_msg_type_autoconf_search = 0x0007,
    multiap_msg_type_autoconf_resp = 0x0008,
} multiap_msg_type_t;


typedef char multiap_short_string_t[64];
typedef unsigned char multiap_enum_type_t;

typedef struct {
    mac_address_t dst;
    mac_address_t src;
    unsigned short type;
} __attribute__((__packed__)) multiap_raw_hdr_t;


typedef struct {
    unsigned char type;
    unsigned short len;
    unsigned char value[0];
} __attribute__((__packed__)) multiap_tlv_t;


typedef struct {
    unsigned char ver;
    unsigned char reserved;
    unsigned short type;
    unsigned short id;
    unsigned char frag_id;
    unsigned char reserved_field : 6;
    unsigned char relay_ind : 1;
    unsigned char last_frag_ind : 1;
} __attribute__((__packed__)) multiap_cmdu_t;


typedef enum {
    multiap_tlv_type_eom = 0,
    multiap_tlv_type_lq = 6,
    multiap_tlv_type_searched_role =0x0d,
} multiap_tlv_type_t;
#endif

void dhcp_sniffer_stop();
void dhcp_sniffer_start();
#ifdef __cplusplus
}
#endif

#endif // WIFI_LINKQUALITY_H
