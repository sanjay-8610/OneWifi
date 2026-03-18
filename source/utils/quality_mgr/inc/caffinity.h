
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

#ifndef CAFFINITY_H
#define CAFFINITY_H

#include <pthread.h>
#include <cjson/cJSON.h>
#include "collection.h"
#include "linkq.h"
#include "run_qmgr.h"
#include <vector>
#include <algorithm>

class caffinity_t
{
    pthread_mutex_t m_lock;
    pthread_mutex_t m_vec_lock;
    mac_addr_str_t m_mac;
    unsigned int m_auth_failures;
    unsigned int m_auth_attempts;
    unsigned int m_assoc_failures;
    unsigned int m_assoc_attempts;
    unsigned int m_dhcp_failures;
    unsigned int m_dhcp_attempts;
    unsigned int m_snr_assoc;
    bool m_connected;
    struct timespec  m_disconnected_time;
    struct timespec  m_connected_time;
    struct timespec  m_sleep_time;
    struct timespec  m_total_time;
    std::vector<stats_arg_t> m_stats_arr;
public:
    caffinity_t(mac_addr_str_t *mac);
    ~caffinity_t();
    int init(stats_arg_t *stats);
    int update_affinity_stats(affinity_arg_t *arg);
    int update_dhcp_stats(unsigned char *mac, uint32_t dhcp_attempts, uint32_t dhcp_failures);
    int score();
    double run_algorithm_caffinity();
   
};

#endif
