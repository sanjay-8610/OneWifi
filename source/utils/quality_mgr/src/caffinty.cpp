
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

int caffinity_t::init(stats_arg_t *stats)
{
    if (!stats) {
        wifi_util_error_print(WIFI_CTRL, "caffinity %s:%d NULL stats pointer\n", __func__, __LINE__);
        return -1;
    }

    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Updating SNR for MAC %s, cli_SNR=%d, channel_utilization=%d\n",
        __func__, __LINE__, stats->mac_str, stats->dev.cli_SNR, stats->channel_utilization);

    pthread_mutex_lock(&m_lock);
    m_cli_snr = stats->dev.cli_SNR;
    m_channel_utilization = stats->channel_utilization;
    
    // Update m_connected status based on cli_Active and cli_AuthenticationState
    bool client_active = (stats->dev.cli_Active && stats->dev.cli_AuthenticationState);
    
    if (client_active != m_connected) {
        m_connected = client_active;
        if (m_connected) {
            clock_gettime(CLOCK_REALTIME, &m_connected_time);
        } else {
            clock_gettime(CLOCK_REALTIME, &m_disconnected_time);
        }
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Connection status changed for MAC %s: was=%d now=%d (cli_Active=%d cli_AuthenticationState=%d)\n",
            __func__, __LINE__, stats->mac_str, !m_connected, m_connected,
            stats->dev.cli_Active, stats->dev.cli_AuthenticationState);
    }
    
    pthread_mutex_unlock(&m_lock);

    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Updated stats for MAC %s with SNR=%d, channel_util=%d, m_connected=%d\n",
        __func__, __LINE__, stats->mac_str, m_cli_snr, m_channel_utilization, m_connected);

    return 0;  // Success
}

int caffinity_t::update_affinity_stats(affinity_arg_t *arg)
{
    wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d event=%d\n", __func__, __LINE__, arg->event);
    
    pthread_mutex_lock(&m_lock);
    
    // Store RSSI from frame for use with unconnected clients
    m_rssi = arg->sig_dbm;
    
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
                m_connected = false;
                clock_gettime(CLOCK_REALTIME, &m_disconnected_time);
                wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d ASSOC/REASSOC response FAILED (status=%u), failures=%u, m_connected=false\n",
                    __func__, __LINE__, arg->status_code, m_assoc_failures);
            } else {
                m_connected = true;
                clock_gettime(CLOCK_REALTIME, &m_connected_time);
                wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d ASSOC/REASSOC response SUCCESS (status=%u), m_connected=true\n",
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
            m_connected = false;
            clock_gettime(CLOCK_REALTIME, &m_disconnected_time);
            wifi_util_info_print(WIFI_CTRL, "caffinity CAFF %s:%d DISASSOC device, m_connected=false\n", __func__, __LINE__);
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

double caffinity_t::run_algorithm_caffinity()
{
    double score = 0.0;
    double failure_ratio = 0.0;
    double auth_failure_rate = 0.0;
    double assoc_failure_rate = 0.0;
    double dhcp_failure_rate = 0.0;
    double snr_normalized = 0.0;
    double snr_squared = 0.0;
    double sigmoid_factor = 0.0;
    double exponent = 0.0;
    int channel_utilization = 0;
    int cli_snr = 0;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Computing caffinity score for MAC %s\n", 
        __func__, __LINE__, m_mac);
    
    pthread_mutex_lock(&m_lock);
    
    // For unconnected clients, use RSSI instead of SNR (SNR is 0 for unassociated)
    // For connected clients, use SNR as before
    if (!m_connected && m_rssi != 0) {
        // Convert RSSI (dBm) to SNR-like value for score calculation
        // RSSI range: typically -90 dBm (bad) to -30 dBm (excellent)
        // Map to approximate SNR range 0-70
        // Formula: snr_equivalent = max(0, min(70, (rssi + 90)))
        cli_snr = m_rssi + 90;  // e.g., -30 dBm -> 60, -90 dBm -> 0
        if (cli_snr < 0) cli_snr = 0;
        if (cli_snr > 70) cli_snr = 70;
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Unconnected client, using RSSI=%d dBm -> equivalent SNR=%d\n",
            __func__, __LINE__, m_rssi, cli_snr);
    } else {
        // Get the current SNR from member variables (for connected clients)
        cli_snr = m_cli_snr;
    }
    channel_utilization = m_channel_utilization;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d cli_SNR=%d, channel_utilization=%d\n",
        __func__, __LINE__, cli_snr, channel_utilization);
    
    // Calculate failure rates with division-by-zero protection
    if (m_auth_attempts > 0) {
        auth_failure_rate = (double)m_auth_failures / (double)m_auth_attempts;
    }
    
    if (m_assoc_attempts > 0) {
        assoc_failure_rate = (double)m_assoc_failures / (double)m_assoc_attempts;
    }
    
    // For unconnected clients (m_connected == false), set dhcp_failure_rate to 0
    if (m_connected) {
        if (m_dhcp_attempts > 0) {
            dhcp_failure_rate = (double)m_dhcp_failures / (double)m_dhcp_attempts;
        }
    } else {
        dhcp_failure_rate = 0.0;
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Client not connected, setting dhcp_failure_rate=0.0\\n",
            __func__, __LINE__);
    }
    
    pthread_mutex_unlock(&m_lock);
    
    // Sum failure rates
    failure_ratio = auth_failure_rate + assoc_failure_rate + dhcp_failure_rate;
    
    // Clamp failure_ratio to [0, 1]
    if (failure_ratio < 0.0) failure_ratio = 0.0;
    if (failure_ratio > 1.0) failure_ratio = 1.0;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d failure_ratio=%.4f (auth=%.4f, assoc=%.4f, dhcp=%.4f)\n",
        __func__, __LINE__, failure_ratio, auth_failure_rate, assoc_failure_rate, dhcp_failure_rate);
    
    // Normalize SNR to [0, 1] range
    // Assuming max SNR is 70 
    if (cli_snr > 0) {
        snr_normalized = (double)cli_snr / 70.0;
    } else {
        snr_normalized = 0.0;
    }
    
    // Clamp snr_normalized to [0, 1]
    if (snr_normalized < 0.0) snr_normalized = 0.0;
    if (snr_normalized > 1.0) snr_normalized = 1.0;
    
    // Square the normalized SNR
    snr_squared = snr_normalized * snr_normalized;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d snr_normalized=%.4f, snr_squared=%.4f\n",
        __func__, __LINE__, snr_normalized, snr_squared);
    
    // Compute sigmoid factor: 1 / (1 + exp(-(b0 + b1 * channel_utilization)))
    // Using LINK_QTY_B0 and LINK_QTY_B1 constants
    exponent = -(LINK_QTY_B0 + LINK_QTY_B1 * channel_utilization);
    
    // Clamp exponent to safe range for numerical stability
    if (exponent < -50.0) exponent = -50.0;
    if (exponent > 50.0) exponent = 50.0;
    
    sigmoid_factor = 1.0 / (1.0 + exp(exponent));
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d exponent=%.4f, sigmoid_factor=%.4f\n",
        __func__, __LINE__, exponent, sigmoid_factor);
    
    // Calculate final score: (1 - failure_ratio) * snr_squared * sigmoid_factor
    score = (1.0 - failure_ratio) * snr_squared * sigmoid_factor;
    
    // Clamp final score to [0, 1]
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d FINAL SCORE=%.4f for MAC %s connected %d\n",
        __func__, __LINE__, score, m_mac, m_connected);
    
    return score;
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
    m_cli_snr = 0;
    m_rssi = 0;
    m_channel_utilization = 0;
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
