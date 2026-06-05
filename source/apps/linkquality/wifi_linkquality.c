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
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include "wifi_hal.h"
#include "wifi_base.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "wifi_apps_mgr.h"
#include "wifi_linkquality.h"
#include "wifi_linkquality_libs.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"
#include "scheduler.h"
#include "common/ieee802_11_defs.h"
#include "lq_ipc_sender.h"


int dhcp_sniffer_fd = -1;
int dhcp_sniffer_ifindex = -1;

static int dhcp_sniffer_running = 0;
static pthread_t dhcp_sniffer_thread;
static volatile int dhcp_sniffer_exit = 0;

#define MAX_STR_LEN 128
#define MAX_BUFF_LEN 1048
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5

static char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";

static void lq_wei_receiver_poll(wifi_app_t *app);
static uint16_t lq_extract_target_ies(const uint8_t *ies, int ies_len,
                                      uint8_t *out_buf, uint16_t out_buf_sz,
                                      uint8_t *vendor_count_out);

static int dhcp_get_msg_type(uint8_t *options, ssize_t options_len)
{
    while (options_len > 0)
    {
        uint8_t type = options[0];

        if (type == DHCP_OPTION_END)
            break;

        if (type == DHCP_OPTION_PAD)
        {
            options++;
            options_len--;
            continue;
        }

        uint8_t len = options[1];

        if (type == DHCP_OP_MSG_TYPE)
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
    int vap_index = -1;
    int radio_index = -1;
    
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

    //wifi_util_dbg_print(WIFI_CTRL," DHCP %s:%d ENTERING dhcp_process_packet, len=%zd\n", __func__, __LINE__, len);

    // ============================================================================
    // STEP 1: Basic packet validation
    // ============================================================================
    if (len < eth_hdr_len + 20 + udp_hdr_len) {  // Minimum: Eth + min IP + UDP
        return;
    }

    // ============================================================================
    // STEP 2: Verify it's a UDP packet and get IP header length
    // ============================================================================
    ip_header = (struct iphdr *)(buffer + eth_hdr_len);
    ip_hdr_len = ip_header->ihl * 4;  // ihl is in 4-byte words
    
    if (ip_header->protocol != IPPROTO_UDP) {
        return;
    }

    // ============================================================================
    // STEP 3: Verify it's on DHCP ports (67=server, 68=client)
    // ============================================================================
    udp_header = (struct udphdr *)(buffer + eth_hdr_len + ip_hdr_len);
    dest_port = ntohs(udp_header->dest);
    
    if (!(dest_port == 67 || dest_port == 68)) {
        return;
    }

    // Determine direction based on destination port
    if (dest_port == 67) {
        direction = "CLIENT->SERVER";
    } else {
        direction = "SERVER->CLIENT";
    }

    // ============================================================================
    // STEP 4: Extract DHCP header and client MAC address
    // ============================================================================
    int dhcp_start = eth_hdr_len + ip_hdr_len + udp_hdr_len;
    dhcp = (struct dhcp_data *)(buffer + dhcp_start);
    mac_to_key(dhcp->chaddr, mac_key);

    // ============================================================================
    // STEP 5: Calculate options offset and verify magic cookie
    // ============================================================================
    options_offset = dhcp_start + dhcp_fixed_len;
    
    if (len < options_offset + magic_cookie_len) {
        return;
    }
    
    // Check for DHCP magic cookie (0x63825363)
    uint8_t *magic_cookie_ptr = (uint8_t *)(buffer + options_offset);
    uint32_t magic_cookie = (magic_cookie_ptr[0] << 24) | (magic_cookie_ptr[1] << 16) | 
                            (magic_cookie_ptr[2] << 8) | magic_cookie_ptr[3];
    
    if (magic_cookie != 0x63825363) {
        wifi_util_dbg_print(WIFI_CTRL," DHCP %s:%d Invalid magic cookie, REJECTING\n", __func__, __LINE__);
        return;
    }

    // Options start right after magic cookie
    uint8_t *options = (uint8_t *)(buffer + options_offset + magic_cookie_len);
    ssize_t options_len = len - (options_offset + magic_cookie_len);
    
    msg_type = dhcp_get_msg_type(options, options_len);
    
    // Convert msg_type to string for logging
    switch (msg_type) {
        case DHCP_DISCOVER: msg_type_str = "DISCOVER"; break;
        case DHCP_OFFER:    msg_type_str = "OFFER";    break;
        case DHCP_REQUEST:  msg_type_str = "REQUEST";  break;
        case DHCP_DECLINE:  msg_type_str = "DECLINE";  break;
        case DHCP_ACK:      msg_type_str = "ACK";      break;
        case DHCP_NAK:      msg_type_str = "NAK";      break;
        default:            msg_type_str = "UNKNOWN";  break;
    }

    // ============================================================================
    // STEP 7: Validate message type
    // ============================================================================
    if (msg_type < 0) {
        return;
    }

    // ============================================================================
    // STEP 8: Check if this is a BOOTP packet (op=1 for client->server, op=2 for server->client)
    // ============================================================================
    if (dhcp->op != DHCP_BOOTP && dhcp->op != 2) {
        return;
    }

    // ============================================================================
    // STEP 9: Pass raw DHCP message type to caffinity via get_lq_descriptor()->periodic_caffinity_stats_update_fn
    // ============================================================================
    wifi_util_info_print(WIFI_CTRL," DHCP %s:%d Processing %s packet for MAC=%s (%s)\n",
        __func__, __LINE__, msg_type_str, mac_key, direction);
    
    // Prepare stats_arg_t and call get_lq_descriptor()->periodic_caffinity_stats_update_fn with raw msg_type
    stats_arg_t affinity_arg;
    memset(&affinity_arg, 0, sizeof(stats_arg_t));
    strncpy(affinity_arg.mac_str, mac_key, sizeof(affinity_arg.mac_str) - 1);
    affinity_arg.vap_index = (unsigned int)vap_index;
    affinity_arg.radio_index = (unsigned int)radio_index;
    affinity_arg.event = 0;  // Not a WiFi management frame event
    affinity_arg.dhcp_event = DHCP_EVENT_UPDATE;
    affinity_arg.dhcp_msg_type = msg_type;  // Pass raw msg_type (1-6)
    
    get_lq_descriptor()->periodic_caffinity_stats_update_fn(&affinity_arg,1);
    
    wifi_util_info_print(WIFI_CTRL," DHCP %s:%d Successfully processed %s packet for MAC=%s\n",
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
static void *sniffer_thread_func(void *arg)
{
    uint8_t buffer[2048];
    ssize_t len;
    fd_set read_fds;
    struct timeval timeout;
    int ret;

    prctl(PR_SET_NAME, "dhcp_sniffer", 0, 0, 0);
    wifi_util_info_print(WIFI_APPS, "%s:%d DHCP sniffer thread started\n", __func__, __LINE__);

    while (!dhcp_sniffer_exit) {
        // Must reinitialize fd_set before each select() call (select modifies it)
        FD_ZERO(&read_fds);
        FD_SET(dhcp_sniffer_fd, &read_fds);
        
        // Use select with timeout to allow checking exit flag
        // TODO: Set timeout to infinite
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
            struct ethhdr *eth = (struct ethhdr *)buffer;
	        uint16_t eth_type = ntohs(eth->h_proto);
            if (eth_type == 0x893a) {  // ETH_P_1905
                wifi_util_info_print(WIFI_CTRL, "%s:%d Received 1905 frame len=%zd\n",
                    __func__, __LINE__, len);
                /* Parse autoconf_resp from EXT and dispatch stats into qmgr */
                lq_handle_1905_frame(buffer, len);
                continue;
            }
            
            // ============================================================================
            // EARLY MAC FILTERING: Check if client MAC is associated via wifi_associated_dev_t
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
                    
                    // Check if this client is connected using caffinity
                    //if (!is_client_connected(mac_key)) {
                   if (1) {
                        // Client not connected - skip processing entirely
                        wifi_util_dbg_print(WIFI_CTRL, " DHCP %s:%d Client MAC %s NOT connected, SKIPPING packet (early filter)\n", 
                            __func__, __LINE__, mac_key);
                        continue;  // Skip to next packet
                    }
                    
                    wifi_util_dbg_print(WIFI_CTRL, " DHCP %s:%d Client MAC %s is connected, processing packet len=%zd\n", 
                        __func__, __LINE__, mac_key, len);
                }
            }
            
            // If we reach here, either it's a DHCP packet from an associated client,
            // or it's not a DHCP packet (will be filtered out indhcp_process_packet)
            dhcp_process_packet(buffer, len);
        }
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d DHCP sniffer thread exiting\n", __func__, __LINE__);
    return NULL;
}
#if 0
static int attach_kernel_bpf_filter(int sock)
{
    const char *filter_expr =
        "ether proto 0x893a "
        "or (ether proto 0x0800 and udp and (port 67 or port 68)) "
        "or (ether proto 0x86dd and udp and (port 546 or port 547))";

    struct bpf_program prog;
    struct sock_fprog fprog;

    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 2048);
    if (!pcap) {
        wifi_util_info_print(WIFI_APPS, "%s:%d: pcap_open_dead failed\n", __func__, __LINE__);
        return -1;
    }

    if (pcap_compile(pcap, &prog, filter_expr, 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d: pcap_compile failed: %s\n", __func__, __LINE__,
                pcap_geterr(pcap));
        pcap_close(pcap);
        return -1;
    }

    fprog.len = prog.bf_len;
    fprog.filter = (struct sock_filter *)prog.bf_insns;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &fprog, sizeof(fprog)) < 0) {
        wifi_util_info_print(WIFI_APPS, "%s:%d: SO_ATTACH_FILTER failed: %s\n", __func__, __LINE__, strerror(errno));
        pcap_freecode(&prog);
        pcap_close(pcap);
        return -1;
    }

    pcap_freecode(&prog);
    pcap_close(pcap);

    return 0;
}
#endif
void dhcp_sniffer_start()
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
#if 0
    if (attach_kernel_bpf_filter(dhcp_sniffer_fd) < 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to attach BPF filter\n", __func__, __LINE__);
        close(dhcp_sniffer_fd);
        return;
    }
#endif
    /* GW(RPI): backhaul to XB8 is eth0 — receives both DHCP and 1905 frames from XB8.
     * For production GW (LAN-side clients): change to "brlan0". */
    // Bind to backhaul interface
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
    dhcp_sniffer_ifindex = ifr.ifr_ifindex;
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
    
    ret = pthread_create(&dhcp_sniffer_thread, &attr, sniffer_thread_func, NULL);
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

void dhcp_sniffer_stop()
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
    char str[MAX_STR_LEN_LQ] = { '\0' };
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
        snprintf(str, MAX_STR_LEN_LQ, "Non-Serviceable");
    } else if (score >= threshold) {
        current_state = 1;
        snprintf(str, MAX_STR_LEN_LQ, "Serviceable");
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
        get_lq_descriptor()->register_station_mac_fn(str);
        //qmgr_register_score_callback(publish_station_score);
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
        get_lq_descriptor()->unregister_station_mac_fn(str);
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
    radio_max_snr_t max_snr = {0};
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    
    
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    if (rfc_param->link_quality_rfc) {
          wifi_util_error_print(WIFI_CTRL,"%s:%d start link_event \n", __func__, __LINE__);
    }
    get_lq_descriptor()->start_link_metrics_fn();


    /* qmgr callbacks and max-SNR setup run on both GW and Extender */
    if (ctrl->network_mode == rdk_dev_mode_type_em_node
      || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node) {
        //qmgr_register_batch_callback(publish_qmgr_subdoc);
        wifi_util_info_print(WIFI_APPS, "%s:%d ctrl->network_mode=%d\n",
            __func__, __LINE__, ctrl->network_mode);
    }

    if (rfc_param->radio_2g_observed_max_snr == 0 || rfc_param->radio_5g_observed_max_snr == 0 ||
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d setting max_snr\n", __func__, __LINE__);
    } else {
        max_snr.radio_2g_max_snr = rfc_param->radio_2g_observed_max_snr;
        max_snr.radio_5g_max_snr = rfc_param->radio_5g_observed_max_snr;
        max_snr.radio_6g_max_snr = rfc_param->radio_6g_observed_max_snr;
        wifi_util_error_print(WIFI_CTRL, "%s:%d setting max_snr\n", __func__, __LINE__);
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d %d:%d:%d\n", __func__, __LINE__,
        max_snr.radio_2g_max_snr, max_snr.radio_5g_max_snr, max_snr.radio_6g_max_snr);
    //set_max_snr_radios(&max_snr);
    //qmgr_register_max_snr_callback(update_radio_max_snr_observance);
    return RETURN_OK;
}

int link_quality_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);

    get_lq_descriptor()->stop_link_metrics_fn();

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

     get_lq_descriptor()->disconnect_link_stats_fn(stats);
    return RETURN_OK;

}
int link_quality_gw_discovery(wifi_app_t *apps, wifi_event_t *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d \n",
        __func__, __LINE__);
    /* GW: broadcast autoconf_search so EXT learns our MAC and can address
     * subsequent autoconf_resp frames to us.
     * GW(RPI): backhaul to XB8 = eth0; for production GW: change to "brlan0". */
     //lq_send_autoconf_search("brlan0");

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
    get_lq_descriptor()->reinit_link_metrics_fn(args);
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

            get_lq_descriptor()->reinit_link_metrics_fn(server_arg);
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
 
     get_lq_descriptor()->remove_link_stats_fn(stats);
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
        get_lq_descriptor()->reinit_link_metrics_fn(server_arg);

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
    stats_arg_t *stats_array = malloc(sizeof(stats_arg_t) * num_devs);
    if (!stats_array) {
        return RETURN_ERR;
    }
    for (int i = 0; i < num_devs; i++) {
       stats_array[i] = data[i].stats;
        wifi_util_dbg_print(
            WIFI_APPS,
            "%s:%d idx=%d mac=%s  snr=%d phy=%d\n",
            __func__, __LINE__,
            i,
            stats_array[i].mac_str,
            stats_array[i].dev.cli_SNR,
            stats_array[i].dev.cli_LastDataDownlinkRate,
            stats_array[i].vap_index
        );
    }
    get_lq_descriptor()->process_lq_stats_fn(stats_array, num_devs);
    free(stats_array);

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
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(event->sub_type));
            break;
    }
    return RETURN_OK;
}


/* ============================================================================
 * IE Extraction Utility
 * Extract SSID, Supported Rates, and Vendor IEs (max 4) into TLV buffer.
 * Returns total bytes written. Sets *vendor_count_out.
 * ============================================================================ */
static uint16_t lq_extract_target_ies(const uint8_t *ies, int ies_len,
                                      uint8_t *out_buf, uint16_t out_buf_sz,
                                      uint8_t *vendor_count_out)
{
    uint16_t offset = 0;
    int vendor_count = 0;
    const uint8_t *ptr = ies;
    int remaining = ies_len;

    while (remaining >= 2 && offset < out_buf_sz) {
        uint8_t id = ptr[0];
        uint8_t len = ptr[1];
        if (remaining < 2 + len) break;

        bool extract = false;
        if (id == LQ_IE_ID_SSID || id == LQ_IE_ID_SUPPORTED_RATES) {
            extract = true;
        } else if (id == LQ_IE_ID_VENDOR_SPECIFIC && vendor_count < MAX_STATS_VENDOR_IES) {
            extract = true;
            vendor_count++;
        }

        if (extract && (offset + 2 + len <= out_buf_sz)) {
            out_buf[offset++] = id;
            out_buf[offset++] = len;
            memcpy(out_buf + offset, ptr + 2, len);
            offset += len;
        }

        ptr += 2 + len;
        remaining -= 2 + len;
    }
    *vendor_count_out = (uint8_t)vendor_count;
    return offset;
}

/* ============================================================================
 * WEI -> OneWifi IPC Receiver
 * ============================================================================ */

static int lq_wei_receiver_init(wifi_app_t *app)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d socket() failed: %s\n", __func__, __LINE__, strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LQ_ONEWIFI_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    unlink(LQ_ONEWIFI_SOCKET_PATH);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d bind(%s) failed: %s\n", __func__, __LINE__,
            LQ_ONEWIFI_SOCKET_PATH, strerror(errno));
        close(fd);
        return -1;
    }

    app->data.u.linkquality.wei_recv_sock = fd;
    wifi_util_info_print(WIFI_APPS,
        "%s:%d WEI receiver socket bound to %s (fd=%d)\n",
        __func__, __LINE__, LQ_ONEWIFI_SOCKET_PATH, fd);
    return 0;
}

static void lq_wei_receiver_poll(wifi_app_t *app)
{
    int fd = app->data.u.linkquality.wei_recv_sock;
    if (fd < 0) return;

    uint8_t buf[16];
    ssize_t n;

    while ((n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        if (n < 3) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d WEI msg too short (%zd bytes)\n", __func__, __LINE__, n);
            continue;
        }

        uint8_t msg_type = buf[0];
        uint16_t payload_len = (uint16_t)buf[1] | ((uint16_t)buf[2] << 8);
        const uint8_t *payload = buf + 3;

        if (3 + payload_len > n) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d WEI msg truncated: declared=%u actual=%zd\n",
                __func__, __LINE__, payload_len, n - 3);
            continue;
        }

        switch (msg_type) {
        case LQ_IPC_MSG_DISCONNECT_CLIENTS_COUNT:
        {
            if (payload_len < sizeof(lq_disconnect_count_t)) break;
            const lq_disconnect_count_t *dc = (const lq_disconnect_count_t *)payload;
            wifi_util_info_print(WIFI_APPS,
                "WEI-RECV %s:%d DISCONNECT_CLIENTS_COUNT=%u (prev=%u)\n",
                __func__, __LINE__, dc->count,
                app->data.u.linkquality.disconnect_count);

            app->data.u.linkquality.disconnect_count = dc->count;
            app->data.u.linkquality.send_probe_auth_assoc = (dc->count > 0);
            break;
        }
        default:
            wifi_util_error_print(WIFI_APPS,
                "WEI-RECV %s:%d unknown msg_type=%u from WEI, ignoring\n",
                __func__, __LINE__, msg_type);
            break;
        }
    }
}

/* ============================================================================
 * Assoc Request Store: store IE data on request, send on successful response
 * ============================================================================ */

static void lq_evict_oldest_assoc_req(wifi_app_t *app)
{
    hash_map_t *map = app->data.u.linkquality.assoc_req_store;
    lq_assoc_req_store_t *elem;
    lq_assoc_req_store_t *oldest = NULL;
    char *oldest_key = NULL;

    elem = (lq_assoc_req_store_t *)hash_map_get_first(map);
    while (elem != NULL) {
        if (oldest == NULL ||
            (elem->timestamp.tv_sec < oldest->timestamp.tv_sec) ||
            (elem->timestamp.tv_sec == oldest->timestamp.tv_sec &&
             elem->timestamp.tv_nsec < oldest->timestamp.tv_nsec)) {
            oldest = elem;
            oldest_key = elem->mac_str;
        }
        elem = (lq_assoc_req_store_t *)hash_map_get_next(map, elem);
    }

    if (oldest_key) {
        elem = (lq_assoc_req_store_t *)hash_map_remove(map, oldest_key);
        if (elem) {
            wifi_util_dbg_print(WIFI_APPS,
                "%s:%d Evicted oldest assoc_req_store entry mac=%s\n",
                __func__, __LINE__, oldest_key);
            free(elem);
        }
    }
}

static void lq_store_assoc_req(wifi_app_t *app, frame_data_t *msg, int sub_event)
{
    mac_addr_str_t mac_str = { 0 };
    to_mac_str(msg->frame.sta_mac, mac_str);

    /* Compute IE offset based on frame type */
    unsigned int fixed_len;
    if (sub_event == wifi_event_hal_reassoc_req_frame) {
        fixed_len = 24 + 10;
    } else {
        fixed_len = 24 + 4;
    }

    const uint8_t *ies = (msg->frame.len > fixed_len) ? (msg->data + fixed_len) : NULL;
    int ies_len = (msg->frame.len > fixed_len) ? (int)(msg->frame.len - fixed_len) : 0;

    pthread_mutex_lock(&app->data.u.linkquality.assoc_req_lock);

    if (app->data.u.linkquality.assoc_req_store == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d assoc_req_store is NULL\n", __func__, __LINE__);
        pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
        return;
    }

    /* Enforce max entries */
    if (hash_map_count(app->data.u.linkquality.assoc_req_store) >= MAX_LQ_ASSOC_REQ_STORE) {
        lq_assoc_req_store_t *existing = (lq_assoc_req_store_t *)hash_map_get(
            app->data.u.linkquality.assoc_req_store, mac_str);
        if (!existing) {
            lq_evict_oldest_assoc_req(app);
        }
    }

    lq_assoc_req_store_t *elem = (lq_assoc_req_store_t *)hash_map_get(
        app->data.u.linkquality.assoc_req_store, mac_str);

    if (elem == NULL) {
        elem = (lq_assoc_req_store_t *)malloc(sizeof(lq_assoc_req_store_t));
        if (!elem) {
            wifi_util_error_print(WIFI_APPS, "%s:%d malloc failed\n", __func__, __LINE__);
            pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
            return;
        }
        memset(elem, 0, sizeof(lq_assoc_req_store_t));
        hash_map_put(app->data.u.linkquality.assoc_req_store, strdup(mac_str), elem);
    }

    /* Populate/update stored data */
    memcpy(elem->mac_str, mac_str, sizeof(mac_addr_str_t));
    elem->ap_index = msg->frame.ap_index;
    elem->sig_dbm = msg->frame.sig_dbm;
    elem->sub_event = sub_event;
    clock_gettime(CLOCK_REALTIME, &elem->timestamp);

    /* Extract and store IEs */
    if (ies && ies_len > 0) {
        elem->ie_data_len = lq_extract_target_ies(ies, ies_len,
            elem->ie_data, MAX_STATS_IE_DATA_LEN, &elem->vendor_ie_count);
    } else {
        elem->ie_data_len = 0;
        elem->vendor_ie_count = 0;
    }

    wifi_util_info_print(WIFI_APPS,
        "ASSOC-STORE %s:%d Stored assoc req: mac=%s vap=%d rssi=%d ie_len=%u vendor_ie=%u\n",
        __func__, __LINE__, mac_str, elem->ap_index, elem->sig_dbm,
        elem->ie_data_len, elem->vendor_ie_count);

    pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
}

/*
 * On successful assoc response: retrieve stored assoc req data,
 * populate stats_arg_t and send LQ_IPC_MSG_ASSOC_REQ_DATA to WEI.
 */
static void lq_send_assoc_req_data(wifi_app_t *app, const char *sta_mac_str)
{
    pthread_mutex_lock(&app->data.u.linkquality.assoc_req_lock);

    lq_assoc_req_store_t *stored = NULL;
    if (app->data.u.linkquality.assoc_req_store != NULL) {
        stored = (lq_assoc_req_store_t *)hash_map_get(
            app->data.u.linkquality.assoc_req_store, (char *)sta_mac_str);
    }

    if (stored == NULL) {
        wifi_util_info_print(WIFI_APPS,
            "ASSOC-REQ-DATA %s:%d No stored assoc req for STA=%s, skipping\n",
            __func__, __LINE__, sta_mac_str);
        pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
        return;
    }

    /* Build stats_arg_t with stored IE data */
    stats_arg_t data;
    memset(&data, 0, sizeof(data));
    strncpy(data.mac_str, stored->mac_str, sizeof(data.mac_str) - 1);
    data.vap_index = (unsigned int)stored->ap_index;
    data.rssi = stored->sig_dbm;
    data.frame_timestamp = stored->timestamp;
    data.frame_type = LQ_FRAME_TYPE_ASSOC;
    data.vendor_ie_count = stored->vendor_ie_count;
    data.ie_data_len = stored->ie_data_len;
    if (stored->ie_data_len > 0) {
        memcpy(data.ie_data, stored->ie_data, stored->ie_data_len);
    }

    wifi_util_info_print(WIFI_APPS,
        "ASSOC-REQ-DATA %s:%d Sending LQ_IPC_MSG_ASSOC_REQ_DATA: mac=%s vap=%u "
        "rssi=%d ie_len=%u vendor_ie=%u\n",
        __func__, __LINE__, data.mac_str, data.vap_index,
        data.rssi, data.ie_data_len, data.vendor_ie_count);

    /* Remove from store after sending */
    lq_assoc_req_store_t *removed = (lq_assoc_req_store_t *)hash_map_remove(
        app->data.u.linkquality.assoc_req_store, (char *)sta_mac_str);
    if (removed) {
        free(removed);
    }

    pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);

    /* Send IPC event */
    lq_ipc_send(LQ_IPC_MSG_ASSOC_REQ_DATA, &data, 1, sizeof(stats_arg_t));
}

/* ============================================================================
 * Auth Event Handler
 * ============================================================================ */
int link_quality_apps_auth_event(wifi_app_t *app, bool req, int sub_event, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    frame_data_t *msg = (frame_data_t *)arg;
    stats_arg_t *affinity_arg = (stats_arg_t *)malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS, " %s:%d unable to alloc memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(affinity_arg, 0, sizeof(stats_arg_t));
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);

    /* Filter: drop events except private VAPs */
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr != NULL) {
        if (is_vap_private(&mgr->hal_cap.wifi_prop, msg->frame.ap_index) != TRUE) {
            wifi_util_info_print(WIFI_APPS,
                "%s:%d dropping MAC: %s: vap_index=%u is not a private VAP\n",
                __func__, __LINE__, affinity_arg->mac_str, msg->frame.ap_index);
            free(affinity_arg);
            return 0;
        }
    }

    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);
    affinity_arg->status_code = 0;

    if (req) {
        affinity_arg->event = sub_event;

        /* Poll WEI receiver for disconnect count updates */
        lq_wei_receiver_poll(app);

        /* Embed frame metadata so WEI can run correlation via CAFFINITY_EVENT.
         * Auth frames carry no IEs — frame_type alone is enough for MAC/VAP match. */
        affinity_arg->frame_type = LQ_FRAME_TYPE_AUTH;
        affinity_arg->rssi = msg->frame.sig_dbm;
        clock_gettime(CLOCK_REALTIME, &affinity_arg->frame_timestamp);
        if (!app->data.u.linkquality.send_probe_auth_assoc) {
            affinity_arg->frame_type = LQ_FRAME_TYPE_NONE;
        }

        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
    }

    free(affinity_arg);
    return RETURN_OK;
}

/* ============================================================================
 * Assoc/Reassoc Event Handler
 * ============================================================================ */
int link_quality_apps_assoc_event(wifi_app_t *app, bool req, int sub_event, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "Enter %s:%d sub_event=%d req=%d\n",
        __func__, __LINE__, sub_event, req);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    stats_arg_t *affinity_arg = (stats_arg_t *)malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS, " %s:%d unable to alloc memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(affinity_arg, 0, sizeof(stats_arg_t));
    frame_data_t *msg = (frame_data_t *)arg;

    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);

    /* Filter: drop events except private VAPs */
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr != NULL) {
        if (is_vap_private(&mgr->hal_cap.wifi_prop, msg->frame.ap_index) != TRUE) {
            wifi_util_info_print(WIFI_APPS,
                "%s:%d dropping MAC: %s: vap_index=%u is not a private VAP\n",
                __func__, __LINE__, affinity_arg->mac_str, msg->frame.ap_index);
            free(affinity_arg);
            return 0;
        }
    }

    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);

    if (req) {
        wifi_util_info_print(WIFI_APPS, "re/assoc req %s:%d\n", __func__, __LINE__);
        affinity_arg->event = sub_event;

        /* Store assoc req data (RSSI, timestamp, IEs) for use on successful response */
        lq_store_assoc_req(app, msg, sub_event);

        /* Poll WEI receiver for disconnect count updates */
        lq_wei_receiver_poll(app);

        /* Embed frame metadata so WEI can run correlation via CAFFINITY_EVENT.
         * Populate IEs only when disconnected clients require matching. */
        affinity_arg->frame_type = LQ_FRAME_TYPE_ASSOC;
        affinity_arg->rssi = msg->frame.sig_dbm;
        clock_gettime(CLOCK_REALTIME, &affinity_arg->frame_timestamp);
        if (app->data.u.linkquality.send_probe_auth_assoc) {
            unsigned int fixed_len = (sub_event == wifi_event_hal_reassoc_req_frame)
                ? (24 + 10) : (24 + 4);
            const uint8_t *assoc_ies = (msg->frame.len > fixed_len)
                ? (msg->data + fixed_len) : NULL;
            int assoc_ies_len = (msg->frame.len > fixed_len)
                ? (int)(msg->frame.len - fixed_len) : 0;
            if (assoc_ies && assoc_ies_len > 0) {
                affinity_arg->ie_data_len = lq_extract_target_ies(
                    assoc_ies, assoc_ies_len,
                    affinity_arg->ie_data, MAX_STATS_IE_DATA_LEN,
                    &affinity_arg->vendor_ie_count);
            }
        } else {
            affinity_arg->frame_type = LQ_FRAME_TYPE_NONE;
        }

        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
    } else {
        wifi_util_info_print(WIFI_APPS, "re/assoc resp %s:%d\n", __func__, __LINE__);
        if ((sub_event == wifi_event_hal_assoc_rsp_frame) ||
            (sub_event == wifi_event_hal_reassoc_rsp_frame)) {
            struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)&msg->data;
            uint16_t status = le_to_host16(frame->u.assoc_resp.status_code);
            wifi_util_info_print(WIFI_CTRL, " %s:%d assoc_rsp status_code=%d\n",
                __func__, __LINE__, status);

            if (status != 0) {
                wifi_util_error_print(WIFI_CTRL,
                    "CAFF %s:%d ASSOC FAILURE MAC=%s sub_event=%d status_code=%u vap=%u radio=%u\n",
                    __func__, __LINE__, affinity_arg->mac_str, sub_event, status,
                    affinity_arg->vap_index, affinity_arg->radio_index);
            }
            affinity_arg->event = sub_event;
            affinity_arg->status_code = status;

            if (status == 0) {
                /* Add AP BSSID */
                wifi_vap_info_t *vap_info = getVapInfo(msg->frame.ap_index);
                if (vap_info != NULL) {
                    to_mac_str(vap_info->u.bss_info.bssid, affinity_arg->ap_mac_str);
                    wifi_util_info_print(WIFI_CTRL, " %s:%d AP BSSID: %s for STA: %s\n",
                        __func__, __LINE__, affinity_arg->ap_mac_str, affinity_arg->mac_str);
                }

                /* Send stored assoc req IEs to WEI via LQ_IPC_MSG_ASSOC_REQ_DATA */
                mac_addr_str_t sta_mac_str = { 0 };
                to_mac_str(msg->frame.sta_mac, sta_mac_str);
                lq_send_assoc_req_data(app, sta_mac_str);
            } else {
                /* Response failure: remove from assoc_req_store */
                mac_addr_str_t sta_mac_str = { 0 };
                to_mac_str(msg->frame.sta_mac, sta_mac_str);

                wifi_util_info_print(WIFI_APPS,
                    "%s:%d Response failure (status=%u), removing STA=%s from assoc_req_store\n",
                    __func__, __LINE__, status, sta_mac_str);

                pthread_mutex_lock(&app->data.u.linkquality.assoc_req_lock);
                if (app->data.u.linkquality.assoc_req_store != NULL) {
                    lq_assoc_req_store_t *removed = (lq_assoc_req_store_t *)hash_map_remove(
                        app->data.u.linkquality.assoc_req_store, sta_mac_str);
                    if (removed) free(removed);
                }
                pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
            }

            get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
        }
    }
    wifi_util_info_print(WIFI_APPS, "Exit %s:%d\n", __func__, __LINE__);
    free(affinity_arg);
    return RETURN_OK;
}

/* ============================================================================
 * Disassoc Event Handler
 * ============================================================================ */
int link_quality_apps_disassoc_event(wifi_app_t *app, bool req, int sub_event, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    frame_data_t *msg = (frame_data_t *)arg;
    stats_arg_t *affinity_arg = (stats_arg_t *)malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS, " %s:%d unable to alloc memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(affinity_arg, 0, sizeof(stats_arg_t));
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);

    /* Filter: drop events except private VAPs */
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr != NULL) {
        if (is_vap_private(&mgr->hal_cap.wifi_prop, msg->frame.ap_index) != TRUE) {
            wifi_util_info_print(WIFI_APPS,
                "%s:%d dropping MAC: %s: vap_index=%u is not a private VAP\n",
                __func__, __LINE__, affinity_arg->mac_str, msg->frame.ap_index);
            free(affinity_arg);
            return 0;
        }
    }

    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);

    if (req) {
        affinity_arg->event = sub_event;
        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
    }

    free(affinity_arg);
    return RETURN_OK;
}

/* ============================================================================
 * Probe Request Event Handler
 * ============================================================================ */
static void lq_dump_probe_req_frame(frame_data_t *msg)
{
    struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)msg->data;
    mac_addr_str_t sa_str = { 0 };
    mac_addr_str_t da_str = { 0 };
    mac_addr_str_t bssid_str = { 0 };

    to_mac_str(frame->sa, sa_str);
    to_mac_str(frame->da, da_str);
    to_mac_str(frame->bssid, bssid_str);

    wifi_util_info_print(WIFI_APPS,
        "PROBE_REQ %s:%d ap_index=%d len=%d sig_dbm=%d phy_rate=%d recv_freq=%d "
        "sa=%s da=%s bssid=%s\n",
        __func__, __LINE__,
        msg->frame.ap_index, msg->frame.len, msg->frame.sig_dbm,
        msg->frame.phy_rate, msg->frame.recv_freq,
        sa_str, da_str, bssid_str);

    unsigned int mgmt_hdr_len = 24;
    if (msg->frame.len > mgmt_hdr_len) {
        const uint8_t *ie = msg->data + mgmt_hdr_len;
        int ie_len = msg->frame.len - mgmt_hdr_len;

        /* Log SSID and whether it's wildcard or directed */
        const uint8_t *ptr = ie;
        int remaining = ie_len;
        while (remaining >= 2) {
            uint8_t id = ptr[0];
            uint8_t len = ptr[1];
            if (remaining < 2 + len) break;
            if (id == LQ_IE_ID_SSID) {
                if (len > 0) {
                    char ssid_str[33] = { 0 };
                    int copy_len = (len < 32) ? len : 32;
                    memcpy(ssid_str, ptr + 2, copy_len);
                    ssid_str[copy_len] = '\0';
                    wifi_util_info_print(WIFI_APPS,
                        "PROBE_REQ %s:%d SSID=\"%s\" (len=%d) - directed probe\n",
                        __func__, __LINE__, ssid_str, len);
                } else {
                    wifi_util_info_print(WIFI_APPS,
                        "PROBE_REQ %s:%d SSID is wildcard/broadcast (len=0) - undirected probe\n",
                        __func__, __LINE__);
                }
                break;
            }
            ptr += 2 + len;
            remaining -= 2 + len;
        }

        wifi_util_dbg_print(WIFI_APPS,
            "PROBE_REQ %s:%d IEs total_len=%d\n", __func__, __LINE__, ie_len);
    }
}

static int link_quality_probe_req_event(wifi_app_t *apps, void *arg)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    frame_data_t *msg = (frame_data_t *)arg;
    struct ieee80211_mgmt *frame = (struct ieee80211_mgmt *)msg->data;
    mac_addr_str_t mac_str = { 0 };

    to_mac_str(frame->sa, mac_str);

    /* Filter: drop events except private VAPs */
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr != NULL) {
        if (is_vap_private(&mgr->hal_cap.wifi_prop, msg->frame.ap_index) != TRUE) {
            return 0;
        }
    }

    /* Debug dump */
    lq_dump_probe_req_frame(msg);

    /* Poll WEI receiver for disconnect count updates */
    lq_wei_receiver_poll(apps);

    /* If disconnected clients exist, send probe data to WEI via CAFFINITY_EVENT.
     * Probes must NOT go through periodic_caffinity_stats_update_fn — that would
     * create a new qmgr entry.  Send directly so WEI does match-only. */
    if (apps->data.u.linkquality.send_probe_auth_assoc) {
        stats_arg_t probe_data;
        memset(&probe_data, 0, sizeof(probe_data));
        strncpy(probe_data.mac_str, mac_str, sizeof(probe_data.mac_str) - 1);
        probe_data.vap_index  = (unsigned int)msg->frame.ap_index;
        probe_data.frame_type = LQ_FRAME_TYPE_PROBE;
        probe_data.rssi       = msg->frame.sig_dbm;
        clock_gettime(CLOCK_REALTIME, &probe_data.frame_timestamp);
        unsigned int mgmt_hdr = 24;
        const uint8_t *ies = (msg->frame.len > mgmt_hdr) ? (msg->data + mgmt_hdr) : NULL;
        int ies_len = (msg->frame.len > mgmt_hdr) ? (int)(msg->frame.len - mgmt_hdr) : 0;
        if (ies && ies_len > 0) {
            probe_data.ie_data_len = lq_extract_target_ies(
                ies, ies_len, probe_data.ie_data, MAX_STATS_IE_DATA_LEN,
                &probe_data.vendor_ie_count);
        }
        wifi_util_info_print(WIFI_APPS,
            "PROBE %s:%d Sending CAFFINITY_EVENT mac=%s vap=%u rssi=%d "
            "ie_len=%u vendor_ie=%u\n",
            __func__, __LINE__, mac_str, probe_data.vap_index, probe_data.rssi,
            probe_data.ie_data_len, probe_data.vendor_ie_count);
        lq_ipc_send(LQ_IPC_MSG_CAFFINITY_EVENT, &probe_data, 1, sizeof(stats_arg_t));
    }

    return RETURN_OK;
}

/* ============================================================================
 * HAL Indication Dispatcher
 * ============================================================================ */
int exec_event_hal_ind(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_util_info_print(WIFI_APPS, " %s:%d\n", __func__, __LINE__);
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
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_auth_event(apps, true, sub_type, arg);
            break;

        case wifi_event_hal_deauth_frame:
            link_quality_apps_auth_event(apps, true, sub_type, arg);
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            break;

        case wifi_event_hal_assoc_req_frame:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_assoc_event(apps, true, sub_type, arg);
            break;

        case wifi_event_hal_assoc_rsp_frame:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_assoc_event(apps, false, sub_type, arg);
            break;

        case wifi_event_hal_reassoc_req_frame:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_assoc_event(apps, true, sub_type, arg);
            break;

        case wifi_event_hal_reassoc_rsp_frame:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_assoc_event(apps, false, sub_type, arg);
            break;

        case wifi_event_hal_sta_conn_status:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_assoc_event(apps, false, sub_type, arg);
            break;

        case wifi_event_hal_disassoc_device:
            wifi_util_info_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_apps_disassoc_event(apps, true, sub_type, arg);
            break;

        case wifi_event_hal_probe_req_frame:
            wifi_util_dbg_print(WIFI_APPS, " %s:%d event = %d\n", __func__, __LINE__, sub_type);
            link_quality_probe_req_event(apps, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
                wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

/* ============================================================================
 * Top-level Event Router
 * ============================================================================ */
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

/* ============================================================================
 * Init / Deinit
 * ============================================================================ */
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

    /* Initialize assoc request store */
    app->data.u.linkquality.assoc_req_store = hash_map_create();
    pthread_mutex_init(&app->data.u.linkquality.assoc_req_lock, NULL);

    /* Initialize WEI receiver socket for LQ_IPC_MSG_DISCONNECT_CLIENTS_COUNT */
    app->data.u.linkquality.wei_recv_sock = -1;
    app->data.u.linkquality.disconnect_count = 0;
    app->data.u.linkquality.send_probe_auth_assoc = false;
    lq_wei_receiver_init(app);

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
    wifi_util_info_print(WIFI_APPS, "%s:%d: Linkstats app data elems registered\n", __func__, __LINE__);
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

    /* Cleanup assoc_req_store */
    pthread_mutex_lock(&app->data.u.linkquality.assoc_req_lock);
    if (app->data.u.linkquality.assoc_req_store) {
        lq_assoc_req_store_t *elem = (lq_assoc_req_store_t *)hash_map_get_first(
            app->data.u.linkquality.assoc_req_store);
        while (elem) {
            lq_assoc_req_store_t *tmp = elem;
            elem = (lq_assoc_req_store_t *)hash_map_get_next(
                app->data.u.linkquality.assoc_req_store, elem);
            hash_map_remove(app->data.u.linkquality.assoc_req_store, tmp->mac_str);
            free(tmp);
        }
        hash_map_destroy(app->data.u.linkquality.assoc_req_store);
        app->data.u.linkquality.assoc_req_store = NULL;
    }
    pthread_mutex_unlock(&app->data.u.linkquality.assoc_req_lock);
    pthread_mutex_destroy(&app->data.u.linkquality.assoc_req_lock);

    /* Cleanup WEI receiver socket */
    if (app->data.u.linkquality.wei_recv_sock >= 0) {
        close(app->data.u.linkquality.wei_recv_sock);
        app->data.u.linkquality.wei_recv_sock = -1;
        unlink(LQ_ONEWIFI_SOCKET_PATH);
    }

    return RETURN_OK;
}
