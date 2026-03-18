
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

    pthread_mutex_lock(&m_vec_lock);
    if (m_stats_arr.empty()) {
        // First time - create new entry
        stats_arg_t new_stats;
        memset(&new_stats, 0, sizeof(stats_arg_t));
        strncpy(new_stats.mac_str, stats->mac_str, sizeof(new_stats.mac_str) - 1);
        new_stats.mac_str[sizeof(new_stats.mac_str) - 1] = '\0';
        new_stats.dev.cli_SNR = stats->dev.cli_SNR;
        new_stats.channel_utilization = stats->channel_utilization;
        m_stats_arr.push_back(new_stats);
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Created new stats entry for MAC %s with SNR=%d, channel_util=%d\n",
            __func__, __LINE__, stats->mac_str, stats->dev.cli_SNR, stats->channel_utilization);
    } else {
        // Update existing entry - update cli_SNR and channel_utilization
        m_stats_arr[0].dev.cli_SNR = stats->dev.cli_SNR;
        m_stats_arr[0].channel_utilization = stats->channel_utilization;
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Updated existing stats for MAC %s with SNR=%d, channel_util=%d\n",
            __func__, __LINE__, stats->mac_str, stats->dev.cli_SNR, stats->channel_utilization);
    }
    pthread_mutex_unlock(&m_vec_lock);

    return 0;
}

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
    bool has_stats = false;
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d Computing caffinity score for MAC %s\n", 
        __func__, __LINE__, m_mac);
    
    // Check if stats are available first
    pthread_mutex_lock(&m_vec_lock);
    if (!m_stats_arr.empty()) {
        cli_snr = m_stats_arr[0].dev.cli_SNR;
        channel_utilization = m_stats_arr[0].channel_utilization;
        has_stats = true;
        wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d cli_SNR=%d, channel_utilization=%d\n",
            __func__, __LINE__, cli_snr, channel_utilization);
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "caffinity %s:%d m_stats_arr is empty for MAC %s, returning -1.0\n",
            __func__, __LINE__, m_mac);
    }
    pthread_mutex_unlock(&m_vec_lock);
    
    // Return -1.0 to indicate stats not available yet
    if (!has_stats) {
        return -1.0;
    }
    
    pthread_mutex_lock(&m_lock);
    
    // Calculate failure rates with division-by-zero protection
    if (m_auth_attempts > 0) {
        auth_failure_rate = (double)m_auth_failures / (double)m_auth_attempts;
    }
    
    if (m_assoc_attempts > 0) {
        assoc_failure_rate = (double)m_assoc_failures / (double)m_assoc_attempts;
    }
    
    if (m_dhcp_attempts > 0) {
        dhcp_failure_rate = (double)m_dhcp_failures / (double)m_dhcp_attempts;
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
    // Assuming max SNR is 25 (can be adjusted based on radio type)
    if (cli_snr > 0) {
        snr_normalized = (double)cli_snr / 25.0;
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
    
    wifi_util_info_print(WIFI_CTRL, "caffinity %s:%d FINAL SCORE=%.4f for MAC %s\n",
        __func__, __LINE__, score, m_mac);
    
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
    pthread_mutex_init(&m_vec_lock, NULL);
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
   pthread_mutex_destroy(&m_vec_lock);
   m_stats_arr.clear();
}
