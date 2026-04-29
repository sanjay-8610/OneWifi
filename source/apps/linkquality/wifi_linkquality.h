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


#include "wifi_base.h"
#include "wifi_hal.h"

#define MAX_STR_LEN_LQ 128
#define MAX_BUFF_LEN 1048
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5

#define BUFFER_SIZE 65536
#define DHCP_BOOTP 1
#define DHCP_OPTION_PAD 0           // DHCP option padding
#define DHCP_OPTION_END 255         // DHCP option end marker
#define DHCP_OPTION_HOSTNAME 12
#define DHCP_OP_MSG_TYPE 53         // DHCP message type option
#define DHCP_OPTION_VENDOR_CLASS_ID 60

/* Types are defined in wifi_apps_mgr.h (inlined to be path-independent).
 * Include it transitively via wifi_ctrl.h, or directly if needed. */

#define MAC_ADDRESS_LEN 6
typedef uint8_t mac_address_t[MAC_ADDRESS_LEN];

#ifdef __cplusplus
}
#endif

#endif // WIFI_LINKQUALITY_H
