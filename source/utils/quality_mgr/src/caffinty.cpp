
/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linkq.h"
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "wifi_util.h"
#include "wifi_events.h"
#include "caffinity.h"

int caffinity_t::update_affinity_stats(affinity_arg_t *arg)
{
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d event=%d\n", __func__, __LINE__, arg->event);
    
    pthread_mutex_lock(&m_lock);
    
    switch(arg->event)
    {
        case wifi_event_hal_auth_frame:
            m_auth_attempts++;
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d AUTH attempt, total=%u\n", 
                __func__, __LINE__, m_auth_attempts);
            break;

        case wifi_event_hal_deauth_frame:
            m_auth_failures++;
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d DEAUTH failure, total=%u\n",
                __func__, __LINE__, m_auth_failures);
            break;

        case wifi_event_hal_assoc_req_frame:
        case wifi_event_hal_reassoc_req_frame:
            m_assoc_attempts++;
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d ASSOC/REASSOC request, attempts=%u\n",
                __func__, __LINE__, m_assoc_attempts);
            break;

        case wifi_event_hal_assoc_rsp_frame:
        case wifi_event_hal_reassoc_rsp_frame:
            // Only increment failure if status_code is non-zero
            if (arg->status_code != 0) {
                m_assoc_failures++;
                wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d ASSOC/REASSOC response FAILED (status=%u), failures=%u\n",
                    __func__, __LINE__, arg->status_code, m_assoc_failures);
            } else {
                wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d ASSOC/REASSOC response SUCCESS (status=%u)\n",
                    __func__, __LINE__, arg->status_code);
            }
            break;

        case wifi_event_hal_sta_conn_status:
            {
                wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d wifi_event_hal_sta_conn_status for MAC %s\n",
                    __func__, __LINE__, arg->mac_str);
                // DHCP stats will be updated via update_dhcp_stats() call from wifi_linkquality.c
            }
            break;

        case wifi_event_hal_disassoc_device:
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d DISASSOC device\n", __func__, __LINE__);
            break;

        default:
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d Unhandled event=%d\n",
                __func__, __LINE__, arg->event);
            break;
    }
    
    pthread_mutex_unlock(&m_lock);
    
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d Updated stats for event=%d: auth_attempts=%u auth_failures=%u assoc_attempts=%u assoc_failures=%u\n",
        __func__, __LINE__, arg->event, m_auth_attempts, m_auth_failures, m_assoc_attempts, m_assoc_failures);
    
    return 0;
}

int caffinity_t::update_dhcp_stats(unsigned char *mac, uint32_t dhcp_attempts, uint32_t dhcp_failures)
{
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d Updating DHCP stats for MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
        __func__, __LINE__, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    // Validate that the MAC matches this caffinity object's MAC
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    if (strcasecmp(mac_str, m_mac) != 0) {
        wifi_util_error_print(WIFI_CTRL, "caffinity CAFF %s:%d ERROR: MAC mismatch! Object MAC=%s, Argument MAC=%s\n",
            __func__, __LINE__, m_mac, mac_str);
        return -1;
    }
    
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d MAC validation passed for %s\n",
        __func__, __LINE__, m_mac);
    
    pthread_mutex_lock(&m_lock);
    m_dhcp_attempts = dhcp_attempts;
    m_dhcp_failures = dhcp_failures;
    pthread_mutex_unlock(&m_lock);
    
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d Updated DHCP stats: attempts=%u, failures=%u\n",
        __func__, __LINE__, m_dhcp_attempts, m_dhcp_failures);
    
    return 0;
}

int caffinity_t::score()
{
    int score = 0;
    wifi_util_info_print(WIFI_CTRL, "CAFF %s:%d\n", __func__, __LINE__);
    return score;
}

caffinity_t::caffinity_t(mac_addr_str_t *mac)
{
    strncpy(m_mac, *mac, sizeof(m_mac) - 1);
    m_mac[sizeof(m_mac) - 1] = '\0';
    pthread_mutex_init(&m_lock, NULL);
    m_auth_failures = 0;
    m_auth_attempts = 0;
    m_assoc_failures = 0;
    m_assoc_attempts = 0;
    m_dhcp_failures = 0;
    m_dhcp_attempts = 0;
    m_snr_assoc = 0;
    memset(&m_disconnected_time, 0, sizeof(m_disconnected_time));
    memset(&m_connected_time, 0, sizeof(m_connected_time));
    memset(&m_sleep_time, 0, sizeof(m_sleep_time));
    memset(&m_total_time, 0, sizeof(m_total_time));
    m_connected =  false;

}

caffinity_t::~caffinity_t()
{
   pthread_mutex_destroy(&m_lock);
}
