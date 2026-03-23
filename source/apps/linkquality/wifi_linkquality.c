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

#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "wifi_hal.h"
#include "wifi_base.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "wifi_apps_mgr.h"
#include "wifi_linkquality.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"
#include "scheduler.h"
#include "common/ieee802_11_defs.h"
#include "secure_wrapper.h"

#define MAX_STR_LEN 128
#define MAX_BUFF_LEN 1048
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5

#define DHCP_MAX_CLIENTS 200
#define DHCP_CLEANUP_TIMEOUT 1800

#define BUFFER_SIZE 65536
#define DHCP_BOOTP 1
#define DHCP_OP_MSG_TYPE 53
#define DHCP_OPTION_HOSTNAME 12
#define DHCP_OPTION_VENDOR_CLASS_ID 60
#define DHCP_BOOTP_INDEX 1
#define DHCP_OP_DISCOVER_INDEX 1
#define DHCP_OP_REQUEST_INDEX 3
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6

typedef struct {
    unsigned char mac[6];

    uint32_t discover;
    uint32_t offer;
    uint32_t request;
    uint32_t decline;
    uint32_t ack;
    uint32_t nak;

    time_t disconnect_time;
    int active;
} dhcp_client_stats_t;

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


static hash_map_t *dhcp_client_map_success = NULL;
static hash_map_t *dhcp_client_map_fail = NULL;

static int dhcp_sniffer_fd = -1;
static int dhcp_sniffer_running = 0;
static pthread_t dhcp_sniffer_thread;
static volatile int dhcp_sniffer_exit = 0;

static pthread_mutex_t dhcp_lock = PTHREAD_MUTEX_INITIALIZER;


static char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";

static int dhcp_get_msg_type(uint8_t *options, ssize_t options_len)
{
    while (options_len > 0)
    {
        uint8_t type = options[0];

        if (type == 255)
            break;

        if (type == 0)
        {
            options++;
            options_len--;
            continue;
        }

        uint8_t len = options[1];

        if (type == 53)
            return options[2];

        options += len + 2;
        options_len -= len + 2;
    }

    return -1;
}

static void mac_to_key(const unsigned char *mac, char *key)
{
    snprintf(key, 18,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void dhcp_get_client_stats(unsigned char *mac, uint32_t *dhcp_attempts, uint32_t *dhcp_failures)
{
    dhcp_client_stats_t *stats = NULL;
    char key[18];
    mac_to_key(mac, key);

    wifi_util_error_print(WIFI_CTRL, " SANJI_DHCP %s:%d looking for MAC "
        "%02x:%02x:%02x:%02x:%02x:%02x key=%s\n",
        __func__, __LINE__,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], key);

    pthread_mutex_lock(&dhcp_lock);

    stats = hash_map_get(dhcp_client_map_success, key);
    if (!stats) {
        wifi_util_error_print(WIFI_CTRL, " SANJI_DHCP %s:%d stats not found for key=%s\n",
            __func__, __LINE__, key);
        *dhcp_attempts  = 0;
        *dhcp_failures  = 0;
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }

    *dhcp_attempts = stats->discover;

     uint32_t unacked = (stats->request > stats->ack) ? (stats->request - stats->ack) : 0;
    *dhcp_failures  = stats->nak + stats->decline + unacked;

    wifi_util_error_print(WIFI_CTRL, " SANJI_DHCP %s:%d MAC %02x:%02x:%02x:%02x:%02x:%02x "
        "attempts=%u failures=%u (nak=%u decline=%u unacked=%u)\n",
        __func__, __LINE__,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        *dhcp_attempts, *dhcp_failures,
        stats->nak, stats->decline, unacked);

    pthread_mutex_unlock(&dhcp_lock);
}

static void dhcp_update_counter(unsigned char *mac, int msg_type)
{
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  dhcp update_couneter msg_type=%d\n", 
        __func__, __LINE__, msg_type);
    dhcp_client_stats_t *stats = NULL;
    char key[18];
    mac_to_key(mac,key);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  looking for MAC %02x:%02x:%02x:%02x:%02x:%02x key=%s\n",
        __func__,__LINE__,
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],key);
    
    pthread_mutex_lock(&dhcp_lock);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  hash_map_success count: %d\n",
        __func__,__LINE__, hash_map_count(dhcp_client_map_success));
    
    stats = hash_map_get(dhcp_client_map_success, key);
    if (!stats) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  stats not found for key=%s in success map\n", 
            __func__, __LINE__, key);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  found stats=%p for key=%s\n",
        __func__,__LINE__, stats, key);

    switch(msg_type)
    {
        case DHCPDISCOVER:
            stats->discover++;
            break;

        case DHCPOFFER:
            stats->offer++;
            break;

        case DHCPREQUEST:
            stats->request++;
            break;

        case DHCPDECLINE:
            stats->decline++;
            break;

        case DHCPACK:
            stats->ack++;
            break;

        case DHCPNAK:
            stats->nak++;
            break;

        default:
            break;
    }
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  updated stats D=%u O=%u R=%u DC=%u ACK=%u NAK=%u\n", __func__, __LINE__,
        stats->discover,
        stats->offer,
        stats->request,
        stats->decline,
        stats->ack,
        stats->nak);
    
    // Update caffinity DHCP stats after each DHCP packet
    uint32_t dhcp_attempts = stats->discover;
    uint32_t unacked = (stats->request > stats->ack) ? (stats->request - stats->ack) : 0;
    uint32_t dhcp_failures = stats->nak + stats->decline + unacked;
    
    pthread_mutex_unlock(&dhcp_lock);
    
    // Convert MAC to string and call update_dhcp_stats
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    wifi_util_error_print(WIFI_CTRL," CAFF %s:%d Calling update_dhcp_stats for MAC %s attempts=%u failures=%u\n",
        __func__, __LINE__, mac_str, dhcp_attempts, dhcp_failures);
    
    update_dhcp_stats(mac_str, dhcp_attempts, dhcp_failures);
}

/* Register callback BEFORE starting qmgr */
void publish_qmgr_subdoc(const report_batch_t* report)
{
    webconfig_subdoc_type_t subdoc_type;
    webconfig_subdoc_data_t *data;
    bus_error_t status;
    raw_data_t rdata;
    wifi_app_t *wifi_app = NULL;
    wifi_util_dbg_print(WIFI_WEBCONFIG," %s:%d link_count=%d\n",__func__,__LINE__,report->link_count);
    wifi_util_error_print(WIFI_CTRL," SANJI %s:%d  \n", __func__, __LINE__);
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Error in allocation memory\n", __func__, __LINE__);
        return ;
    }
 
    memset(data, '\0', sizeof(webconfig_subdoc_data_t));
    data->u.decoded.hal_cap = get_wifimgr_obj()->hal_cap;
    for (unsigned int i = 0; i < getNumberRadios(); i++){
        data->u.decoded.radios[i] = get_wifimgr_obj()->radio_config[i];
    }
    data->u.decoded.qmgr_report =  (report_batch_t *)report;
    subdoc_type = webconfig_subdoc_type_link_report;
    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Error in encoding link report\n", __func__,
              __LINE__);
        free(data);
        return;
    }
    memset(&rdata, 0, sizeof(raw_data_t));
    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    wifi_util_dbg_print(WIFI_WEBCONFIG,"raw data=%s\n",(char*)rdata.raw_data.bytes);
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;


    wifi_app = get_app_by_inst(&ctrl->apps_mgr, wifi_app_inst_link_quality);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }
    status = get_bus_descriptor()->bus_event_publish_fn(&wifi_app->ctrl->handle, WIFI_QUALITY_LINKREPORT, &rdata);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, status);
        free(data);
        return ;
    }
    if(data)
        free(data);
    return;
}

static void dhcp_register_client(unsigned char *mac, uint16_t status_code)

{
    dhcp_client_stats_t *stats;
    char key[18];
    char *key_copy = NULL;
    int ret;
    hash_map_t *target_map = NULL;
    const char *map_name = NULL;
    
    mac_to_key(mac,key);
    
    // Determine which map to use based on status code
    if (status_code == 0) {
        target_map = dhcp_client_map_success;
        map_name = "success";
    } else {
        target_map = dhcp_client_map_fail;
        map_name = "fail";
    }
    
    wifi_util_error_print(WIFI_CTRL,
" SANJI_DHCP %s:%d MAC %02x:%02x:%02x:%02x:%02x:%02x key=%s status_code=%u map=%s\n",
__func__,__LINE__,
mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],key,status_code,map_name);
    
    pthread_mutex_lock(&dhcp_lock);

    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d hash_map_%s count before: %d\n",
        __func__,__LINE__, map_name, hash_map_count(target_map));

    if (hash_map_count(target_map) >= DHCP_MAX_CLIENTS) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d max dhcp clients reached in %s map\n",__func__,__LINE__,map_name);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }

    
    if (hash_map_get(target_map,key)) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d client already exists in %s map with key=%s\n",
            __func__,__LINE__,map_name,key);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }

    stats = calloc(1,sizeof(dhcp_client_stats_t));
    if (!stats) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d calloc failed for stats\n",__func__,__LINE__);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }

    memcpy(stats->mac,mac,6);
    stats->active = 1;
    
    // Duplicate the key so it persists after function returns
    key_copy = strdup(key);
    if (!key_copy) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d strdup failed for key\n",__func__,__LINE__);
        free(stats);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d adding client to %s hash map with key=%s stats=%p\n",
        __func__, __LINE__, map_name, key_copy, stats);
    
    ret = hash_map_put(target_map, key_copy, stats);
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d hash_map_put returned: %d\n",
        __func__,__LINE__, ret);
    
    // Verify the entry was added
    dhcp_client_stats_t *verify = hash_map_get(target_map, key_copy);
    if (verify) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d VERIFIED: client added successfully to %s map, stats=%p\n",
            __func__,__LINE__, map_name, verify);
    } else {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d ERROR: verification failed, client not found in %s map!\n",
            __func__,__LINE__, map_name);
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d hash_map_%s count after: %d\n",
        __func__,__LINE__, map_name, hash_map_count(target_map));
    
    pthread_mutex_unlock(&dhcp_lock);
}

static void dhcp_print_and_mark_disconnect(unsigned char *mac)
{
    dhcp_client_stats_t *stats;
    char key[18];
    mac_to_key(mac,key);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  print and mark_disconnect for MAC %02x:%02x:%02x:%02x:%02x:%02x key=%s\n", 
        __func__, __LINE__, 
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], key);
    
    pthread_mutex_lock(&dhcp_lock);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  hash_map_success count: %d\n",
        __func__,__LINE__, hash_map_count(dhcp_client_map_success));
    
    stats = hash_map_get(dhcp_client_map_success,key);
    
    if (!stats) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d  stats not found for key=%s in success map\n", 
            __func__, __LINE__, key);
        pthread_mutex_unlock(&dhcp_lock);
        return;
    }

    wifi_util_error_print(WIFI_CTRL,
        " SANJI_DHCP %s:%d DHCP stats for %02x:%02x:%02x:%02x:%02x:%02x (key=%s stats=%p) D=%u O=%u R=%u DC=%u ACK=%u NAK=%u\n",
        __func__,__LINE__,
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], key, stats,
        stats->discover,
        stats->offer,
        stats->request,
        stats->decline,
        stats->ack,
        stats->nak);

    stats->active = 0;
    stats->disconnect_time = time(NULL);
    
    pthread_mutex_unlock(&dhcp_lock);
}


static void dhcp_process_packet(const uint8_t *buffer, ssize_t len)
{
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct dhcp_data *dhcp;
    char mac_key[18];
    int msg_type;
    uint16_t dest_port;
    const char *msg_type_str = "UNKNOWN";
    const char *direction = "";
    
    // DHCP packet structure offsets:
    // Ethernet (14) + IP (variable, usually 20) + UDP (8) + DHCP header (236) + Magic Cookie (4)
    // DHCP header = op(1) + htype(1) + hlen(1) + hops(1) + xid(4) + secs(2) + flags(2) +
    //               ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4) + chaddr(16) + 
    //               sname(64) + file(128) = 236 bytes
    int eth_hdr_len = sizeof(struct ethhdr);  // 14 bytes
    int ip_hdr_len;   // Variable, calculated from IP header
    int udp_hdr_len = sizeof(struct udphdr);  // 8 bytes
    int dhcp_fixed_len = 236;  // Fixed DHCP header up to magic cookie
    int magic_cookie_len = 4;
    int options_offset;

    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d ========== ENTERING dhcp_process_packet, len=%zd ==========\n", __func__, __LINE__, len);

    // ============================================================================
    // STEP 1: Basic packet validation
    // ============================================================================
    if (len < eth_hdr_len + 20 + udp_hdr_len) {  // Minimum: Eth + min IP + UDP
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Packet too short (len=%zd), REJECTING\n", 
            __func__, __LINE__, len);
        return;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 1: Packet length OK (len=%zd)\n", __func__, __LINE__, len);

    // ============================================================================
    // STEP 2: Verify it's a UDP packet and get IP header length
    // ============================================================================
    ip_header = (struct iphdr *)(buffer + eth_hdr_len);
    ip_hdr_len = ip_header->ihl * 4;  // ihl is in 4-byte words
    
    if (ip_header->protocol != IPPROTO_UDP) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Not UDP (protocol=%d), REJECTING\n", 
            __func__, __LINE__, ip_header->protocol);
        return;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 2: UDP packet confirmed, IP_hdr_len=%d bytes\n", 
        __func__, __LINE__, ip_hdr_len);

    // ============================================================================
    // STEP 3: Verify it's on DHCP ports (67=server, 68=client)
    // ============================================================================
    udp_header = (struct udphdr *)(buffer + eth_hdr_len + ip_hdr_len);
    dest_port = ntohs(udp_header->dest);
    
    if (!(dest_port == 67 || dest_port == 68)) {
        wifi_util_dbg_print(WIFI_CTRL," SANJI_DHCP %s:%d Not DHCP port (dest=%d), REJECTING\n", 
            __func__, __LINE__, dest_port);
        return;
    }

    // Determine direction based on destination port
    if (dest_port == 67) {
        direction = "CLIENT->SERVER";
    } else {
        direction = "SERVER->CLIENT";
    }

    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 3: DHCP packet on port %d (%s)\n", 
        __func__, __LINE__, dest_port, direction);

    // ============================================================================
    // STEP 4: Extract DHCP header and client MAC address
    // ============================================================================
    int dhcp_start = eth_hdr_len + ip_hdr_len + udp_hdr_len;
    dhcp = (struct dhcp_data *)(buffer + dhcp_start);
    mac_to_key(dhcp->chaddr, mac_key);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 4: DHCP starts at offset=%d, client MAC=%s (from chaddr: %02x:%02x:%02x:%02x:%02x:%02x)\n",
        __func__, __LINE__, dhcp_start, mac_key,
        dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2],
        dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]);

    // ============================================================================
    // STEP 5: Verify MAC is in success map (CRITICAL CHECK)
    // ============================================================================
    pthread_mutex_lock(&dhcp_lock);
    dhcp_client_stats_t *client_stats = hash_map_get(dhcp_client_map_success, mac_key);
    
    if (!client_stats) {
        pthread_mutex_unlock(&dhcp_lock);
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 5: Client MAC %s NOT in success map, REJECTING packet\n", 
            __func__, __LINE__, mac_key);
        return;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 5: Client MAC %s VERIFIED in success map (stats=%p)\n", 
        __func__, __LINE__, mac_key, client_stats);
    pthread_mutex_unlock(&dhcp_lock);

    // ============================================================================
    // STEP 6: Calculate options offset and verify magic cookie
    // ============================================================================
    options_offset = dhcp_start + dhcp_fixed_len;
    
    if (len < options_offset + magic_cookie_len) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Packet too short for DHCP options (len=%zd < offset=%d), REJECTING\n",
            __func__, __LINE__, len, options_offset + magic_cookie_len);
        return;
    }
    
    // Check for DHCP magic cookie (0x63825363)
    uint8_t *magic_cookie_ptr = (uint8_t *)(buffer + options_offset);
    uint32_t magic_cookie = (magic_cookie_ptr[0] << 24) | (magic_cookie_ptr[1] << 16) | 
                            (magic_cookie_ptr[2] << 8) | magic_cookie_ptr[3];
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 6: options_offset=%d, magic_cookie=0x%08x (expect 0x63825363)\n",
        __func__, __LINE__, options_offset, magic_cookie);
    
    // Dump first 16 bytes at magic cookie location for debugging
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Magic cookie area (16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
        __func__, __LINE__,
        magic_cookie_ptr[0], magic_cookie_ptr[1], magic_cookie_ptr[2], magic_cookie_ptr[3],
        magic_cookie_ptr[4], magic_cookie_ptr[5], magic_cookie_ptr[6], magic_cookie_ptr[7],
        magic_cookie_ptr[8], magic_cookie_ptr[9], magic_cookie_ptr[10], magic_cookie_ptr[11],
        magic_cookie_ptr[12], magic_cookie_ptr[13], magic_cookie_ptr[14], magic_cookie_ptr[15]);
    
    if (magic_cookie != 0x63825363) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Invalid magic cookie (got 0x%08x, expected 0x63825363), REJECTING\n",
            __func__, __LINE__, magic_cookie);
        return;
    }

    // Options start right after magic cookie
    uint8_t *options = (uint8_t *)(buffer + options_offset + magic_cookie_len);
    ssize_t options_len = len - (options_offset + magic_cookie_len);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Options start at offset=%d, options_len=%zd\n",
        __func__, __LINE__, options_offset + magic_cookie_len, options_len);
    
    // Dump first 32 bytes of options for debugging
    if (options_len >= 32) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d First 32 bytes of options: "
            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            __func__, __LINE__,
            options[0], options[1], options[2], options[3], options[4], options[5], options[6], options[7],
            options[8], options[9], options[10], options[11], options[12], options[13], options[14], options[15],
            options[16], options[17], options[18], options[19], options[20], options[21], options[22], options[23],
            options[24], options[25], options[26], options[27], options[28], options[29], options[30], options[31]);
    }
    
    msg_type = dhcp_get_msg_type(options, options_len);
    
    // Convert msg_type to string for logging
    switch(msg_type) {
        case DHCPDISCOVER: msg_type_str = "DISCOVER"; break;
        case DHCPOFFER:    msg_type_str = "OFFER"; break;
        case DHCPREQUEST:  msg_type_str = "REQUEST"; break;
        case DHCPDECLINE:  msg_type_str = "DECLINE"; break;
        case DHCPACK:      msg_type_str = "ACK"; break;
        case DHCPNAK:      msg_type_str = "NAK"; break;
        default:           msg_type_str = "UNKNOWN"; break;
    }
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 6 RESULT: Parsed DHCP message type=%d (%s), op=%d, direction=%s\n",
        __func__, __LINE__, msg_type, msg_type_str, dhcp->op, direction);

    // ============================================================================
    // STEP 7: Validate message type
    // ============================================================================
    if (msg_type < 0) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 7: Invalid/missing DHCP message type, REJECTING\n", 
            __func__, __LINE__);
        return;
    }

    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 7: Valid DHCP message type\n", __func__, __LINE__);

    // ============================================================================
    // STEP 8: Check if this is a BOOTP packet (op=1 for client->server, op=2 for server->client)
    // ============================================================================
    if (dhcp->op != DHCP_BOOTP && dhcp->op != 2) {
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 8: Not a BOOTP packet (op=%d), REJECTING\n", 
            __func__, __LINE__, dhcp->op);
        return;
    }

    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 8: BOOTP op=%d validated\n", __func__, __LINE__, dhcp->op);

    // ============================================================================
    // STEP 9: Update counter for this message type
    // ============================================================================
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d STEP 9: Calling dhcp_update_counter for MAC=%s, msg_type=%d (%s)\n",
        __func__, __LINE__, mac_key, msg_type, msg_type_str);
    
    dhcp_update_counter(dhcp->chaddr, msg_type);
    
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d ========== SUCCESSFULLY PROCESSED %s packet for MAC=%s ==========\n",
        __func__, __LINE__, msg_type_str, mac_key);
}

static int ignite_score_log_timer(void *args)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_app_t *wifi_app = get_app_by_inst(&ctrl->apps_mgr, wifi_app_inst_link_quality);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ignite_lq_state_t *ignite = &wifi_app->data.u.linkquality.ignite;

    char tmp[128] = { 0 };
    char buff[MAX_BUFF_LEN] = { 0 };

    get_formatted_time(tmp);
    snprintf(buff, sizeof(buff), "%s WIFI_IGNITE_LINKQUALITY:%f %f\n", tmp, ignite->last_score,
        ignite->last_threshold);
    wifi_util_info_print(WIFI_APPS, "%s:%d: %s\n", __func__, __LINE__, buff);
    write_to_file(wifi_health_log, buff);
    return RETURN_OK;
}

static void *dhcp_sniffer_thread_func(void *arg)
{
    uint8_t buffer[2048];
    ssize_t len;
    fd_set read_fds;
    struct timeval timeout;
    int ret;

    prctl(PR_SET_NAME, "dhcp_sniffer", 0, 0, 0);
    wifi_util_info_print(WIFI_APPS, "%s:%d DHCP sniffer thread started\n", __func__, __LINE__);

    while (!dhcp_sniffer_exit) {
        FD_ZERO(&read_fds);
        FD_SET(dhcp_sniffer_fd, &read_fds);
        
        // Use select with timeout to allow checking exit flag
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        ret = select(dhcp_sniffer_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ret < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted, check exit flag and retry
            }
            wifi_util_error_print(WIFI_CTRL, "%s:%d select() failed: %s\n", __func__, __LINE__, strerror(errno));
            break;
        } else if (ret == 0) {
            // Timeout, check exit flag and continue
            continue;
        }
        
        if (FD_ISSET(dhcp_sniffer_fd, &read_fds)) {
            len = recvfrom(dhcp_sniffer_fd, buffer, sizeof(buffer), 0, NULL, NULL);
            
            if (len <= 0) {
                if (len < 0 && errno == EINTR) {
                    continue;
                }
                wifi_util_error_print(WIFI_CTRL, "%s:%d recvfrom() failed or connection closed\n", __func__, __LINE__);
                break;
            }
            
            // ============================================================================
            // EARLY MAC FILTERING: Check if client MAC is in dhcp_client_map_success
            // Parse just enough to extract the client MAC, then filter before full processing
            // ============================================================================
            int dhcp_hdr_sz = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            
            // Basic packet validation
            if (len >= dhcp_hdr_sz + 28 + 16) {  // Need at least DHCP header with chaddr field
                struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                struct udphdr *udp_header = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
                
                // Check if this is a DHCP packet (UDP ports 67 or 68)
                if (ip_header->protocol == IPPROTO_UDP && 
                    (ntohs(udp_header->dest) == 67 || ntohs(udp_header->dest) == 68)) {
                    
                    // Extract client MAC from DHCP chaddr field (offset 28 in DHCP header)
                    struct dhcp_data *dhcp = (struct dhcp_data *)(buffer + dhcp_hdr_sz);
                    char mac_key[18];
                    mac_to_key(dhcp->chaddr, mac_key);
                    
                    // Check if this client is in the success map
                    pthread_mutex_lock(&dhcp_lock);
                    int client_in_success_map = (hash_map_get(dhcp_client_map_success, mac_key) != NULL);
                    pthread_mutex_unlock(&dhcp_lock);
                    
                    if (!client_in_success_map) {
                        // Client not in success map - skip processing entirely
                        wifi_util_dbg_print(WIFI_CTRL, " SANJI_DHCP %s:%d Client MAC %s NOT in success map, SKIPPING packet (early filter)\n", 
                            __func__, __LINE__, mac_key);
                        continue;  // Skip to next packet
                    }
                    
                    wifi_util_dbg_print(WIFI_CTRL, " SANJI_DHCP %s:%d Client MAC %s in success map, processing packet len=%zd\n", 
                        __func__, __LINE__, mac_key, len);
                }
            }
            
            // If we reach here, either it's a DHCP packet from a client in success map,
            // or it's not a DHCP packet (will be filtered out in dhcp_process_packet)
            dhcp_process_packet(buffer, len);
        }
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d DHCP sniffer thread exiting\n", __func__, __LINE__);
    return NULL;
}

static void dhcp_sniffer_start()
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    pthread_attr_t attr;
    int ret;

    
    wifi_util_error_print(WIFI_CTRL, " SANJI %s:%d DHCP sniffer start\n", __func__, __LINE__);
    
    if (dhcp_sniffer_running) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d DHCP sniffer already running\n", __func__, __LINE__);
        return;
    }

    // Create raw socket
    dhcp_sniffer_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (dhcp_sniffer_fd < 0) {
        wifi_util_error_print(WIFI_CTRL, " SANJI %s:%d Failed to create socket: %s\n", __func__, __LINE__, strerror(errno));
        return;
    }

    // Bind to brlan0 interface
    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "brlan0", IFNAMSIZ - 1);
    
    if (ioctl(dhcp_sniffer_fd, SIOCGIFINDEX, &ifr) < 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get interface index: %s\n", __func__, __LINE__, strerror(errno));
        close(dhcp_sniffer_fd);
        dhcp_sniffer_fd = -1;
        return;
    }
    
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(dhcp_sniffer_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to bind socket: %s\n", __func__, __LINE__, strerror(errno));
        close(dhcp_sniffer_fd);
        dhcp_sniffer_fd = -1;
        return;
    }

    // Reset exit flag and create thread
    dhcp_sniffer_exit = 0;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    ret = pthread_create(&dhcp_sniffer_thread, &attr, dhcp_sniffer_thread_func, NULL);
    pthread_attr_destroy(&attr);
    
    if (ret != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to create DHCP sniffer thread: %s\n", __func__, __LINE__, strerror(ret));
        close(dhcp_sniffer_fd);
        dhcp_sniffer_fd = -1;
        return;
    }

    dhcp_sniffer_running = 1;
    wifi_util_info_print(WIFI_CTRL, "%s:%d DHCP sniffer started successfully\n", __func__, __LINE__);
}

static void dhcp_sniffer_stop()
{
    if (!dhcp_sniffer_running) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d DHCP sniffer not running\n", __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d Stopping DHCP sniffer\n", __func__, __LINE__);
    
    // Signal thread to exit
    dhcp_sniffer_exit = 1;
    
    // Close the socket to unblock select/recvfrom
    if (dhcp_sniffer_fd >= 0) {
        close(dhcp_sniffer_fd);
        dhcp_sniffer_fd = -1;
    }

    // Wait for thread to finish (joinable thread)
    wifi_util_error_print(WIFI_CTRL, " SANJI_DHCP %s:%d Waiting for sniffer thread to join\n", __func__, __LINE__);
    pthread_join(dhcp_sniffer_thread, NULL);
    wifi_util_error_print(WIFI_CTRL, " SANJI_DHCP %s:%d Sniffer thread joined\n", __func__, __LINE__);

    dhcp_sniffer_running = 0;
    wifi_util_info_print(WIFI_CTRL, "%s:%d DHCP sniffer stopped\n", __func__, __LINE__);
}

void publish_station_score(const char *input_str, double score, double threshold)
{
    char str[MAX_STR_LEN] = { '\0' };
    int current_state = -1;
    bus_error_t status;
    raw_data_t rdata;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_app_t *wifi_app = get_app_by_inst(&ctrl->apps_mgr, wifi_app_inst_link_quality);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }
    ignite_lq_state_t *ignite = &wifi_app->data.u.linkquality.ignite;

    wifi_util_info_print(WIFI_APPS, "%s:%d str =%s score =%f threshold =%f\n", __func__, __LINE__,
        input_str, score, threshold);

    ignite->last_score = score;
    ignite->last_threshold = threshold;

    if (threshold != 0.0 && ignite->score_log_timer_id == 0) {
        scheduler_add_timer_task(ctrl->sched, FALSE, &ignite->score_log_timer_id,
            ignite_score_log_timer, NULL, IGNITE_SCORE_LOG_INTERVAL_MS, 0, 0);
        wifi_util_info_print(WIFI_APPS, "%s:%d: Started ignite score log timer (15 min)\n",
            __func__, __LINE__);
    }

    if (ignite->last_service_state == -1) {
        ignite->iteration_count++;
        if (ignite->iteration_count < IGNITE_INITIAL_PUBLISH_ITERATIONS) {
            wifi_util_info_print(WIFI_APPS,
                "%s:%d: Waiting for %dth iteration before first publish, current=%d\n",
                __func__, __LINE__, IGNITE_INITIAL_PUBLISH_ITERATIONS,
                ignite->iteration_count);
            return;
        }
    }

    if (score < threshold) {
        current_state = 0;
        snprintf(str, MAX_STR_LEN, "Non-Serviceable");
    } else if (score >= threshold) {
        current_state = 1;
        snprintf(str, MAX_STR_LEN, "Serviceable");
    }

    if (current_state != -1 && current_state != ignite->last_service_state) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: ignite status toggled to %s\n", __func__, __LINE__,
            str);
        memset(&rdata, 0, sizeof(raw_data_t));
        rdata.data_type = bus_data_type_string;
        rdata.raw_data.bytes = (void *)str;
        rdata.raw_data_len = (strlen(str) + 1);

        status = get_bus_descriptor()->bus_event_publish_fn(&wifi_app->ctrl->handle,
            WIFI_IGNITE_STATUS, &rdata);
        if (status != bus_error_success) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
                __func__, __LINE__, status);
        }
        if (ignite->last_service_state == -1) {
            char tmp[128] = { 0 };
            char buff[MAX_BUFF_LEN] = { 0 };
            get_formatted_time(tmp);
            snprintf(buff, sizeof(buff), "%s WIFI_IGNITE_LINKQUALITY:%f %f\n", tmp,
                ignite->last_score, ignite->last_threshold);
            wifi_util_info_print(WIFI_APPS, "%s:%d: Score at first RBUS publish after connection: %s\n", __func__,
                __LINE__, buff);
            write_to_file(wifi_health_log, buff);
        }
        ignite->last_service_state = current_state;
    }

    return;
}

int link_quality_register_station(wifi_app_t *apps, wifi_event_t *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    char *str = (char *)arg;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if ( ctrl->rf_status_down) {
        register_station_mac(str);
        qmgr_register_score_callback(publish_station_score);
    }
    return RETURN_OK;
}

int link_quality_unregister_station(wifi_app_t *apps, wifi_event_t *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    char *str = (char *)arg;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if ( ctrl->rf_status_down) {
        unregister_station_mac(str);
    }

    ignite_lq_state_t *ignite = &apps->data.u.linkquality.ignite;
    if (ignite->score_log_timer_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ignite->score_log_timer_id);
        ignite->score_log_timer_id = 0;
        wifi_util_info_print(WIFI_APPS, "%s:%d: Cancelled ignite score log timer\n", __func__,
            __LINE__);
    }
    ignite->last_service_state = -1;
    ignite->iteration_count = 0;
    unsigned char mac[6];

    sscanf(str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);

    dhcp_print_and_mark_disconnect(mac); 
    return RETURN_OK;
}
int update_radio_max_snr_observance(int radio, int max_snr)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d radio=%d and max_snr=%d\n", __func__, __LINE__,radio,max_snr);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    if (rfc_param == NULL) {
        wifi_util_error_print(WIFI_CTRL, "Unable to fetch CTRL RFC %s:%d\n", __func__, __LINE__);
        return RETURN_OK;
    }
    switch(radio) {
        case 0:
            if ( max_snr > rfc_param->radio_2g_observed_max_snr) {
                rfc_param->radio_2g_observed_max_snr = max_snr ;
            }
            break;
        case 1:
            if ( max_snr > rfc_param->radio_5g_observed_max_snr) {
                rfc_param->radio_5g_observed_max_snr = max_snr;
            }
            break;
        case 2:
            if ( max_snr > rfc_param->radio_6g_observed_max_snr) {
                rfc_param->radio_6g_observed_max_snr = max_snr;
            }
            break;
        default:
            wifi_util_info_print(WIFI_CTRL,"Not a valid radio\n");

    }
    get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);
    return RETURN_OK;
}
int link_quality_event_exec_start(wifi_app_t *apps, void *arg)
{
      
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    
    // Create dhcp_client_map_success if not already created
    if (!dhcp_client_map_success) {
        dhcp_client_map_success = hash_map_create();
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d dhcp_client_map_success hash_map created\n", __func__, __LINE__);
    }
    
    // Create dhcp_client_map_fail if not already created
    if (!dhcp_client_map_fail) {
        dhcp_client_map_fail = hash_map_create();
        wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d dhcp_client_map_fail hash_map created\n", __func__, __LINE__);
    }
    
    // Start DHCP sniffer
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Starting DHCP sniffer\n", __func__, __LINE__);
    dhcp_sniffer_start();
    
    if ( ctrl->network_mode == rdk_dev_mode_type_em_node
      || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node) {
        qmgr_register_batch_callback(publish_qmgr_subdoc);
        wifi_util_info_print(WIFI_APPS, "%s:%d ctrl->network_mode=%d\n", __func__, __LINE__,ctrl->network_mode);
    } 
    radio_max_snr_t max_snr = {0};
    //qmgr_register_callback(publish_qmgr_subdoc);
    start_link_metrics();
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    if (rfc_param->link_quality_rfc) {
          wifi_util_error_print(WIFI_CTRL,"%s:%d start link_event \n", __func__, __LINE__);
    }
    if (rfc_param->radio_2g_observed_max_snr == 0 || rfc_param->radio_5g_observed_max_snr == 0|| 
        rfc_param->radio_6g_observed_max_snr == 0) {
        if (rfc_param->radio_2g_observed_max_snr == 0) {
            max_snr.radio_2g_max_snr = 25;
            rfc_param->radio_2g_observed_max_snr = 25;
	} else {
            max_snr.radio_2g_max_snr = rfc_param->radio_2g_observed_max_snr;
	}
        if (rfc_param->radio_5g_observed_max_snr == 0) {
            max_snr.radio_5g_max_snr = 25;
            rfc_param->radio_5g_observed_max_snr = 25;
	} else {
            max_snr.radio_5g_max_snr = rfc_param->radio_5g_observed_max_snr;
	}
        if (rfc_param->radio_6g_observed_max_snr == 0) {
            max_snr.radio_6g_max_snr = 25;
            rfc_param->radio_6g_observed_max_snr = 25;
	} else {
            max_snr.radio_6g_max_snr = rfc_param->radio_6g_observed_max_snr;
	}
        get_wifidb_obj()->desc.update_rfc_config_fn(0, rfc_param);

          wifi_util_error_print(WIFI_CTRL,"%s:%d setting max_snr \n", __func__, __LINE__);
    } else {
	max_snr.radio_2g_max_snr = rfc_param->radio_2g_observed_max_snr;
	max_snr.radio_5g_max_snr = rfc_param->radio_5g_observed_max_snr;
        max_snr.radio_6g_max_snr = rfc_param->radio_6g_observed_max_snr;
        wifi_util_error_print(WIFI_CTRL,"%s:%d setting max_snr \n", __func__, __LINE__);
    }
    
    wifi_util_info_print(WIFI_APPS, "%s:%d %d:%d:%d \n", __func__, __LINE__,
    max_snr.radio_2g_max_snr,max_snr.radio_5g_max_snr,max_snr.radio_6g_max_snr);
    set_max_snr_radios(&max_snr);
    wifi_util_error_print(WIFI_CTRL," SANJI %s:%d calling update_radio_max_snr_observance \n", __func__, __LINE__);
    qmgr_register_max_snr_callback(update_radio_max_snr_observance);
    return RETURN_OK;
}

int link_quality_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    
    // Stop DHCP sniffer
    wifi_util_error_print(WIFI_CTRL," SANJI_DHCP %s:%d Stopping DHCP sniffer\n", __func__, __LINE__);
    dhcp_sniffer_stop();
    
    stop_link_metrics();

    ignite_lq_state_t *ignite = &apps->data.u.linkquality.ignite;
    if (ignite->score_log_timer_id != 0) {
        scheduler_cancel_timer_task(apps->ctrl->sched, ignite->score_log_timer_id);
        ignite->score_log_timer_id = 0;
        wifi_util_info_print(WIFI_APPS, "%s:%d: Cancelled ignite score log timer\n", __func__,
            __LINE__);
    }
    ignite->last_service_state = -1;
    ignite->iteration_count = 0;

    return RETURN_OK;
}

int link_quality_hal_rapid_connect(wifi_app_t *apps, void *arg)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;
    stats_arg_t *stats = &data->stats;
    wifi_util_error_print(
        WIFI_APPS,
        "%s:%d  mac=%s  snr=%d phy=%d\n",
        __func__, __LINE__,
        stats->mac_str,
        stats->dev.cli_SNR,
        stats->dev.cli_LastDataDownlinkRate
    );

    disconnect_link_stats(stats);
    return RETURN_OK;

}
int link_quality_ignite_reinit_param(wifi_app_t *apps, wifi_event_t *arg)
{
    if (!arg) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    linkquality_data_t *data = (linkquality_data_t *)arg;
    server_arg_t *args = &data->server_arg;
    reinit_link_metrics(args);
    wifi_util_info_print(WIFI_APPS, "%s:%d sampling = %d reportingl as %d and threshold as %f\n",
        __func__, __LINE__,args->sampling, args->reporting, args->threshold);
    return RETURN_OK;

}
int link_quality_param_reinit(wifi_app_t *apps, wifi_event_t *arg)
{

#ifdef EM_APP
    if (!arg) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    //linkquality_data_t *data = (linkquality_data_t *)arg;

    em_config_t *em_config;
    wifi_event_t *event = NULL;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    webconfig_subdoc_data_t *doc;

    if (!arg) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    event = arg;
    doc = (webconfig_subdoc_data_t *)event->u.webconfig_data;
    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    server_arg_t *server_arg = (server_arg_t *)malloc(sizeof(server_arg_t));
    memset(server_arg,0,sizeof(server_arg_t));
    switch (doc->type) {
        case webconfig_subdoc_type_em_config:
            em_config = &decoded_params->em_config;
            if (em_config == NULL) {
                wifi_util_error_print(WIFI_APPS, "%s:%d NULL pointer \n", __func__, __LINE__);
                return RETURN_ERR;
            }

            wifi_util_info_print(WIFI_APPS, "%s:%d Received config Interval as %d and threshold as %f\n",
                __func__, __LINE__, em_config->alarm_report_policy.reporting_interval,
                em_config->alarm_report_policy.link_quality_threshold);
            
            server_arg->reporting = em_config->alarm_report_policy.reporting_interval;
            server_arg->threshold = em_config->alarm_report_policy.link_quality_threshold;

            wifi_util_info_print(WIFI_APPS, "%s:%d reportingl as %d and threshold as %f\n",
                __func__, __LINE__, server_arg->reporting, server_arg->threshold);

            reinit_link_metrics(server_arg);
            free(server_arg);
            break;

        default:
  
            break;
    }
#endif
    return RETURN_OK;
}

int link_quality_hal_disconnect(wifi_app_t *apps, void *arg)
 {           
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;
    stats_arg_t *stats = &data->stats;
    wifi_util_error_print( WIFI_CTRL,
         "%s:%d  mac=%s  snr=%d phy=%d\n",
         __func__, __LINE__,
         stats->mac_str,
         stats->dev.cli_SNR,
         stats->dev.cli_LastDataDownlinkRate
    );      
 
    remove_link_stats(stats);
    return RETURN_OK;
             
 } 

int link_quality_ignite_param_reinit(wifi_app_t *apps, wifi_event_t *arg)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;

     server_arg_t *server_arg = &data->server_arg;
        wifi_util_dbg_print(
            WIFI_APPS,
            "%s:%d  threshold=%f reporting=%d\n",
            __func__, __LINE__,
            server_arg->threshold,
            server_arg->reporting
        );
        reinit_link_metrics(server_arg);

    return RETURN_OK;
}

int link_quality_event_exec_timeout(wifi_app_t *apps, void *arg, int len)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;

    /* The number of devices is stored in the first element */
    int num_devs = len;

    for (int i = 0; i < num_devs; i++) {

        stats_arg_t *stats = &data[i].stats;
        wifi_util_dbg_print(
            WIFI_APPS,
            "%s:%d idx=%d mac=%s  snr=%d phy=%d\n",
            __func__, __LINE__,
            i,
            stats->mac_str,
            stats->dev.cli_SNR,
            stats->dev.cli_LastDataDownlinkRate,
            stats->vap_index
        );

        add_stats_metrics(stats);
    }
    //dhcp_cleanup_old_entries();
    return RETURN_OK;
}

int exec_event_link_quality(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg, int len)
{
    switch (sub_type) {
        case wifi_event_exec_start:
            link_quality_event_exec_start(apps, arg);
            break;

        case wifi_event_exec_stop:
            link_quality_event_exec_stop(apps, arg);
            break;

        case wifi_event_exec_timeout:
            link_quality_event_exec_timeout(apps, arg,len);
            break;
        
        case wifi_event_exec_register_station:
            link_quality_register_station(apps, arg);
            break;
        
        case wifi_event_exec_unregister_station:
            link_quality_unregister_station(apps, arg);
            break;
        
	case wifi_event_exec_link_param_reinit:
            link_quality_ignite_reinit_param(apps, arg);
            break;
        
        
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

int exec_event_webconfig_event(wifi_app_t *apps, wifi_event_t *event)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    switch (event->sub_type) {
        case wifi_event_exec_start:
            break;

        case wifi_event_exec_stop:
            break;

        case wifi_event_webconfig_set_data_ovsm:
            link_quality_param_reinit(apps, event);
            break;
        case wifi_event_exec_timeout:
            link_quality_ignite_param_reinit(apps, event);
            break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(event->sub_type));
            break;
    }
    return RETURN_OK;
}

int link_quality_apps_auth_event(wifi_app_t *app, bool req,int sub_event,void *arg)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
   //Fill the affinity_arg with frame data 
    affinity_arg_t *affinity_arg = ( affinity_arg_t *) malloc(sizeof( affinity_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memry\n",__func__,__LINE__);
       return RETURN_ERR;
    }

    frame_data_t *msg = (frame_data_t *)arg;
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);
    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index,&affinity_arg->channel_utilization);
    affinity_arg->status_code = 0;  // Initialize status_code
    affinity_arg->sig_dbm = msg->frame.sig_dbm;  // Get RSSI from frame
    
    if (req)   {
        affinity_arg->event = sub_event;
        update_affinity_stats(affinity_arg,true);
    }

    update_affinity_stats(affinity_arg,false);
    return RETURN_OK;
}

int link_quality_apps_assoc_event(wifi_app_t *app, bool req,int sub_event,void *arg)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    wifi_util_error_print(WIFI_CTRL," SANJI_EVENT %s:%d sub_event=%d req=%d\n", __func__, __LINE__, sub_event, req);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
   //Fill the affinity_arg with frame data 
    affinity_arg_t *affinity_arg = ( affinity_arg_t *) malloc(sizeof( affinity_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memry\n",__func__,__LINE__);
       return RETURN_ERR;
    }
    frame_data_t *msg = (frame_data_t *)arg;
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);
    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index,&affinity_arg->channel_utilization);
    affinity_arg->status_code = 0;  // Initialize status_code
    affinity_arg->sig_dbm = msg->frame.sig_dbm;  // Get RSSI from frame

    if (req)   {
        affinity_arg->event = sub_event;
        update_affinity_stats(affinity_arg,true);
    } else {
        
        // Check for wifi_event_hal_assoc_rsp_frame sub_event
        if (sub_event == wifi_event_hal_assoc_rsp_frame) {
            struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)&msg->data;
            uint16_t status = le_to_host16(frame->u.assoc_resp.status_code);
            wifi_util_error_print(WIFI_CTRL," CAFF %s:%d wifi_event_hal_assoc_rsp_frame status_code=%d\n", __func__, __LINE__, status);
            
            // Register client in appropriate map based on status code
            dhcp_register_client(msg->frame.sta_mac, status);
            
            // Update caffinity stats via update_affinity_stats with status_code
            affinity_arg->event = sub_event;
            affinity_arg->status_code = status;
            wifi_util_error_print(WIFI_CTRL, " CAFF %s:%d Calling update_affinity_stats for MAC %s, event=%d, status=%d\n",
                __func__, __LINE__, affinity_arg->mac_str, sub_event, status);
            update_affinity_stats(affinity_arg, true);
            
            if (status == 0) {
                // association success
                wifi_util_error_print(WIFI_CTRL," CAFF %s:%d assoc passed, client added to success map\n", __func__, __LINE__);
            } else {
                wifi_util_error_print(WIFI_CTRL," CAFF %s:%d assoc failed, client added to fail map\n", __func__, __LINE__);
            }
        }
        
        if (sub_event == wifi_event_hal_reassoc_rsp_frame) {
            struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)&msg->data;
            if (le_to_host16(frame->u.assoc_resp.status_code) != 0) {
                affinity_arg->event = sub_event;
                update_affinity_stats(affinity_arg,true);
	    } else if (le_to_host16(frame->u.assoc_resp.status_code) != 0) {
                affinity_arg->event = sub_event;
                update_affinity_stats(affinity_arg,true);
	    
            }
        }	    
    }
    free(affinity_arg);
    return RETURN_OK;
}
int link_quality_apps_disassoc_event(wifi_app_t *app, bool req,int sub_event,void *arg)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    wifi_util_error_print(WIFI_CTRL," SANJI %s:%d  \n", __func__, __LINE__);
    
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    
    // Get frame data
    frame_data_t *msg = (frame_data_t *)arg;
    
    // Call dhcp_print_and_mark_disconnect with the station MAC
    dhcp_print_and_mark_disconnect(msg->frame.sta_mac);
    
    // Fill the affinity_arg with frame data 
    affinity_arg_t *affinity_arg = (affinity_arg_t *) malloc(sizeof(affinity_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memory\n",__func__,__LINE__);
        return RETURN_ERR;
    }
    
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);
    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);
    
    if (req) {
        affinity_arg->event = sub_event;
        update_affinity_stats(affinity_arg, true);
    }
    
    free(affinity_arg);
    return RETURN_OK;
}

int exec_event_hal_ind(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
         return RETURN_ERR;
    }
    switch (sub_type) {
        case wifi_event_exec_start:
            break;

        case wifi_event_exec_stop:
            link_quality_hal_disconnect(apps, arg);
            break;

        case wifi_event_exec_timeout:
            link_quality_hal_rapid_connect(apps, arg);
            break;

        case wifi_event_hal_auth_frame:
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_auth_event(apps,true,sub_type,arg);
            break;
        
        case wifi_event_hal_deauth_frame:
            link_quality_apps_auth_event(apps,true,sub_type,arg);
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            break;
     
        case wifi_event_hal_assoc_req_frame:
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_assoc_event(apps,true,sub_type,arg);
            break;
 
        case wifi_event_hal_assoc_rsp_frame:
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_assoc_event(apps,false,sub_type,arg);
            break;

        case wifi_event_hal_reassoc_req_frame:
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_assoc_event(apps,true,sub_type,arg);
            break;
        case wifi_event_hal_reassoc_rsp_frame:
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_assoc_event(apps,true,sub_type,arg);
            break;
     
        case wifi_event_hal_sta_conn_status:
            //move the func call to here
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            //may be here new function has to be used in this case the station has to be moved to connected 
	        link_quality_apps_assoc_event(apps,false,sub_type,arg);
            break;
        case wifi_event_hal_disassoc_device:
            //may be here new function has to be used in this case the station has to be moved to disconnect/removed. 
            wifi_util_info_print(WIFI_APPS," %s:%d event = %d\n",__func__,__LINE__,sub_type);
            link_quality_apps_assoc_event(apps,true,sub_type,arg);
            break;
        
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

int link_quality_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            exec_event_webconfig_event(app, event);
            break;

        case wifi_event_type_exec:
            exec_event_link_quality(app, event->sub_type, event->u.core_data.msg, event->u.core_data.len);
            break;

        case wifi_event_type_hal_ind:
            exec_event_hal_ind(app, event->sub_type, event->u.core_data.msg);
            break;

        default:
            break;
    }

    return RETURN_OK;
}


int link_quality_init(wifi_app_t *app, unsigned int create_flag)
{
    char *component_name = "WifiLinkReport";
    int num_elements = 0;
    int rc = bus_error_success;

    bus_data_element_t dataElements[] = {
        { WIFI_QUALITY_LINKREPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } } ,
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    ignite_lq_state_t *ignite = &app->data.u.linkquality.ignite;
    ignite->last_score = 0.0;
    ignite->last_threshold = 0.0;
    ignite->score_log_timer_id = 0;
    ignite->last_service_state = -1;
    ignite->iteration_count = 0;

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
            __func__, __LINE__, component_name, rc);
        return RETURN_ERR;
    }
    num_elements = (sizeof(dataElements)/sizeof(bus_data_element_t));
    if (get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, dataElements,
        num_elements) != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: failed to register Linkstats app data elements\n", __func__,
        __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Linkstats app data elems registered\n", __func__,__LINE__);
    return RETURN_OK;
}

int link_quality_deinit(wifi_app_t *app)
{
    ignite_lq_state_t *ignite = &app->data.u.linkquality.ignite;
    if (ignite->score_log_timer_id != 0) {
        scheduler_cancel_timer_task(app->ctrl->sched, ignite->score_log_timer_id);
        ignite->score_log_timer_id = 0;
    }
    ignite->last_service_state = -1;
    ignite->iteration_count = 0;
    return RETURN_OK;
}
