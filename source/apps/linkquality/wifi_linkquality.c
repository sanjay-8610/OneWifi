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


#define MAX_BUFF_LEN_lq 1048
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5
#define MAX_STR_LEN 128
#define IGNITE_SCORE_THRESHOLD_BUFF 64
#define NOISE_FLOOR (-95)

static char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";


#ifdef EM_APP
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
#endif

static int ignite_score_log_timer(void *args)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_app_t *wifi_app = get_app_by_inst(&ctrl->apps_mgr, wifi_app_inst_link_quality);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ignite_lq_state_t *ignite = &wifi_app->data.u.linkquality.ignite;

    char tmp[MAX_STR_LEN] = { 0 };
    char buff[MAX_BUFF_LEN_lq] = { 0 };

    get_formatted_time(tmp);
    snprintf(buff, sizeof(buff), "%s WIFI_IGNITE_LINKQUALITY:%f %f %s\n", tmp, ignite->last_score,
        ignite->last_threshold, ignite->ignite_service_status);
    wifi_util_info_print(WIFI_APPS, "%s:%d: %s\n", __func__, __LINE__, buff);
    write_to_file(wifi_health_log, buff);
    return RETURN_OK;
}

void publish_station_score(const char *input_str, double score, double threshold)
{
    char str[MAX_STR_LEN_LQ] = { '\0' };
    int current_state = -1;
    bus_error_t status;
    raw_data_t rdata;
    char tmp[MAX_STR_LEN] = { 0 };
    char buff[MAX_BUFF_LEN_lq] = { 0 };
    char telemetry_val[IGNITE_SCORE_THRESHOLD_BUFF] = {0};
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
        snprintf(ignite->ignite_service_status, MAX_IGNITE_STR_LEN, "Manageable");
    } else if (score >= threshold) {
        current_state = 1;
        snprintf(str, MAX_STR_LEN, "Serviceable");
        snprintf(ignite->ignite_service_status, MAX_IGNITE_STR_LEN, "Serviceable");
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
        get_formatted_time(tmp);
        if (ignite->last_service_state == -1) {
            snprintf(buff, sizeof(buff), "%s WIFI_IGNITE_LINKQUALITY_FIRST_PUBLISH:%f %f %s\n", tmp,
                ignite->last_score, ignite->last_threshold, ignite->ignite_service_status);
            wifi_util_info_print(WIFI_APPS,
                "%s:%d: Score at first RBUS publish after connection: %s\n", __func__, __LINE__,
                buff);
            write_to_file(wifi_health_log, buff);
            snprintf(telemetry_val, IGNITE_SCORE_THRESHOLD_BUFF, "%f %f %s", ignite->last_score,
                ignite->last_threshold, ignite->ignite_service_status);
            get_stubs_descriptor()->t2_event_s_fn("WIFI_IGNITE_LINKQUALITY_FIRST_PUBLISH",
                telemetry_val);
        } else {
            snprintf(buff, sizeof(buff), "%s WIFI_IGNITE_LINKQUALITY_STATE_CHANGE:%f %f %s\n", tmp,
                ignite->last_score, ignite->last_threshold, ignite->ignite_service_status);
            wifi_util_info_print(WIFI_APPS, "%s:%d: State change score: %s\n", __func__, __LINE__,
                buff);
            write_to_file(wifi_health_log, buff);
            snprintf(telemetry_val, IGNITE_SCORE_THRESHOLD_BUFF, "%f %f %s", ignite->last_score,
                ignite->last_threshold, ignite->ignite_service_status);
            get_stubs_descriptor()->t2_event_s_fn("WIFI_IGNITE_LINKQUALITY_STATE_CHANGE",
                telemetry_val);
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
      
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    
    /* qmgr callbacks and max-SNR setup run on both GW and Extender */
    if (ctrl->network_mode == rdk_dev_mode_type_em_node
      || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node) {
#ifdef EM_APP
        get_lq_descriptor()->start_link_metrics_fn();
        qmgr_register_batch_callback(publish_qmgr_subdoc);
         wifi_util_info_print(WIFI_APPS, "%s:%d ctrl->network_mode=%d\n",
            __func__, __LINE__, ctrl->network_mode);
#endif
    }
    return RETURN_OK;
}

int link_quality_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl->network_mode == rdk_dev_mode_type_em_node
      || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node) {


#ifdef EM_APP
        get_lq_descriptor()->stop_link_metrics_fn();
#endif
    }
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

/**
 * parse_and_store_ies - Parse a raw 802.11 IE buffer and store a filtered,
 * deterministically ordered subset into dst.
 *
 * Collected IEs (full tag+len+body):
 *   Tag   0  SSID
 *   Tag   1  Supported Rates
 *   Tag  45  HT Capabilities
 *   Tag  48  RSN (WPA2/WPA3)
 *   Tag 127  Extended Capabilities
 *   Tag 191  VHT Capabilities
 *   Tag 221  Vendor Specific (up to MAX_VENDOR_IES_FOR_FP; WPA/WPS filtered)
 *   Tag 255  HE Capabilities (Extension ID 35)
 *
 * Output order is always canonical regardless of frame order:
 *   SSID → Rates → HT Caps → VHT Caps → HE Caps → Ext Caps → RSN → Vendor IEs
 *
 * Additionally:
 *   ie_order_out  — dash-separated tag sequence in frame-native order
 *                   (tag 255 rendered as "255:EXT_ID")
 *   vendor_count_out — total tag-221 count seen before filter
 *
 * @src              Raw IE bytes from the frame body.
 * @src_len          Length of src in bytes.
 * @dst              Output buffer (ie_data field of stats_arg_t).
 * @dst_max          Capacity of dst (MAX_IE_DATA_LEN).
 * @ie_order_out     Output buffer for IE order string (MAX_IE_ORDER_LEN bytes).
 * @ie_order_max     Capacity of ie_order_out.
 * @vendor_count_out Receives the raw vendor IE count (pre-filter).
 * @return           Number of bytes written to dst.
 */
#define MAX_VENDOR_IES_FOR_FP 4
static uint16_t parse_and_store_ies(const uint8_t *src, uint16_t src_len,
                                     uint8_t *dst, uint16_t dst_max,
                                     char *ie_order_out, uint16_t ie_order_max,
                                     uint8_t *vendor_count_out)
{
    /* --- Per-IE collection buffers --- */
    uint8_t  ssid_buf[257]           = {0}; /* tag(1)+len(1)+up-to-255 */
    uint16_t ssid_total              = 0;
    uint8_t  rates_buf[257]          = {0};
    uint16_t rates_total             = 0;
    uint8_t  ht_buf[30]              = {0}; /* HT Caps: tag+len+26 bytes */
    uint16_t ht_total                = 0;
    uint8_t  vht_buf[16]             = {0}; /* VHT Caps: tag+len+12 bytes */
    uint16_t vht_total               = 0;
    uint8_t  he_buf[64]              = {0}; /* HE Caps: variable, max ~31 */
    uint16_t he_total                = 0;
    uint8_t  extcap_buf[16]          = {0}; /* Ext Caps: variable, typically ≤10 */
    uint16_t extcap_total            = 0;
    uint8_t  rsn_buf[64]             = {0}; /* RSN: variable, typically ≤42 */
    uint16_t rsn_total               = 0;
    uint8_t  vendor_buf[MAX_IE_DATA_LEN] = {0};
    uint16_t vendor_total            = 0;
    int      vendor_count_accepted   = 0;
    int      vendor_count_raw        = 0;

    /* --- IE order string accumulator --- */
    char     order_buf[MAX_IE_ORDER_LEN] = {0};
    int      order_pos               = 0;

    uint16_t offset = 0;

    while (offset + 2 <= src_len) {
        uint8_t tag = src[offset];
        uint8_t len = src[offset + 1];

        if (offset + 2 + len > src_len) {
            break;
        }

        /* --- Record this tag in the IE order string (frame-native order) --- */
        {
            char tok[16] = {0};
            if (tag == 255 && len >= 1) {
                /* Extension IE: render as "255:EXT_ID" */
                snprintf(tok, sizeof(tok), "%s255:%u",
                         order_pos > 0 ? "-" : "", src[offset + 2]);
            } else {
                snprintf(tok, sizeof(tok), "%s%u",
                         order_pos > 0 ? "-" : "", tag);
            }
            int tok_len = (int)strlen(tok);
            if (order_pos + tok_len < (int)ie_order_max - 1) {
                memcpy(&order_buf[order_pos], tok, tok_len);
                order_pos += tok_len;
            }
        }

        /* --- Collect each supported IE into its dedicated buffer --- */
        if (tag == 0) { /* SSID */
            if (ssid_total == 0 && (2 + len) <= (uint16_t)sizeof(ssid_buf)) {
                ssid_buf[0] = tag;
                ssid_buf[1] = len;
                memcpy(&ssid_buf[2], &src[offset + 2], len);
                ssid_total = 2 + len;
            }
        } else if (tag == 1) { /* Supported Rates */
            if (rates_total == 0 && (2 + len) <= (uint16_t)sizeof(rates_buf)) {
                rates_buf[0] = tag;
                rates_buf[1] = len;
                memcpy(&rates_buf[2], &src[offset + 2], len);
                rates_total = 2 + len;
            }
        } else if (tag == 45) { /* HT Capabilities */
            if (ht_total == 0 && (2 + len) <= (uint16_t)sizeof(ht_buf)) {
                ht_buf[0] = tag;
                ht_buf[1] = len;
                memcpy(&ht_buf[2], &src[offset + 2], len);
                ht_total = 2 + len;
            }
        } else if (tag == 48) { /* RSN */
            if (rsn_total == 0 && (2 + len) <= (uint16_t)sizeof(rsn_buf)) {
                rsn_buf[0] = tag;
                rsn_buf[1] = len;
                memcpy(&rsn_buf[2], &src[offset + 2], len);
                rsn_total = 2 + len;
            }
        } else if (tag == 127) { /* Extended Capabilities */
            if (extcap_total == 0 && (2 + len) <= (uint16_t)sizeof(extcap_buf)) {
                extcap_buf[0] = tag;
                extcap_buf[1] = len;
                memcpy(&extcap_buf[2], &src[offset + 2], len);
                extcap_total = 2 + len;
            }
        } else if (tag == 191) { /* VHT Capabilities */
            if (vht_total == 0 && (2 + len) <= (uint16_t)sizeof(vht_buf)) {
                vht_buf[0] = tag;
                vht_buf[1] = len;
                memcpy(&vht_buf[2], &src[offset + 2], len);
                vht_total = 2 + len;
            }
        } else if (tag == 255) { /* Element ID Extension — check for HE Caps (ext ID 35) */
            if (he_total == 0 && len >= 1 && src[offset + 2] == 35 &&
                (2 + len) <= (uint16_t)sizeof(he_buf)) {
                he_buf[0] = tag;
                he_buf[1] = len;
                memcpy(&he_buf[2], &src[offset + 2], len);
                he_total = 2 + len;
            }
        } else if (tag == 221) { /* Vendor Specific */
            vendor_count_raw++;
            if (vendor_count_accepted < MAX_VENDOR_IES_FOR_FP) {
                /* Skip OUI 00:50:F2 type 1 (WPA) or type 4 (WPS) */
                if (len >= 4) {
                    const uint8_t *oui = &src[offset + 2];
                    if (oui[0] == 0x00 && oui[1] == 0x50 && oui[2] == 0xF2 &&
                        (oui[3] == 1 || oui[3] == 4)) {
                        offset += 2 + len;
                        continue;
                    }
                }
                if ((vendor_total + 2 + len) <= (uint16_t)sizeof(vendor_buf)) {
                    vendor_buf[vendor_total]     = tag;
                    vendor_buf[vendor_total + 1] = len;
                    memcpy(&vendor_buf[vendor_total + 2], &src[offset + 2], len);
                    vendor_total += 2 + len;
                    vendor_count_accepted++;
                }
            }
        }
        offset += 2 + len;
    }

    /* Copy IE order string to output */
    if (ie_order_out && ie_order_max > 0) {
        strncpy(ie_order_out, order_buf, ie_order_max - 1);
        ie_order_out[ie_order_max - 1] = '\0';
    }

    /* Copy raw vendor IE count to output */
    if (vendor_count_out) {
        *vendor_count_out = (uint8_t)(vendor_count_raw <= 255 ? vendor_count_raw : 255);
    }

    /*
     * Write in deterministic canonical order:
     *   SSID → Rates → HT Caps → VHT Caps → HE Caps → Ext Caps → RSN → Vendor IEs
     * This order is fixed regardless of how IEs appeared in the frame.
     */
    uint16_t written = 0;
#define APPEND_IE_BUF(buf, total) \
    do { \
        if ((total) > 0 && (written + (total)) <= dst_max) { \
            memcpy(&dst[written], (buf), (total)); \
            written += (total); \
        } \
    } while (0)

    APPEND_IE_BUF(ssid_buf,   ssid_total);
    APPEND_IE_BUF(rates_buf,  rates_total);
    APPEND_IE_BUF(ht_buf,     ht_total);
    APPEND_IE_BUF(vht_buf,    vht_total);
    APPEND_IE_BUF(he_buf,     he_total);
    APPEND_IE_BUF(extcap_buf, extcap_total);
    APPEND_IE_BUF(rsn_buf,    rsn_total);
    APPEND_IE_BUF(vendor_buf, vendor_total);
#undef APPEND_IE_BUF

    /* ----- Debug: summary ----- */
    wifi_util_dbg_print(WIFI_APPS,
        "parse_and_store_ies: SSID=%s(%uB) Rates=%s(%uB) HT=%s(%uB) VHT=%s(%uB)"
        " HE=%s(%uB) ExtCap=%s(%uB) RSN=%s(%uB) Vendor=%d/%d(%uB)"
        " IE_Order=[%s] total=%uB\n",
        ssid_total   ? "YES" : "NO", ssid_total,
        rates_total  ? "YES" : "NO", rates_total,
        ht_total     ? "YES" : "NO", ht_total,
        vht_total    ? "YES" : "NO", vht_total,
        he_total     ? "YES" : "NO", he_total,
        extcap_total ? "YES" : "NO", extcap_total,
        rsn_total    ? "YES" : "NO", rsn_total,
        vendor_count_accepted, vendor_count_raw, vendor_total,
        order_buf, written);

    /* ----- Debug: human-readable dump of every stored IE ----- */
    {
        uint16_t off = 0;
        int      ie_num = 0;
        wifi_util_dbg_print(WIFI_APPS,
            "------------------------------------------------------------------\n"
            "parse_and_store_ies: IE dump (%u bytes total)\n"
            "------------------------------------------------------------------\n"
            "  #   ID   LEN   CONTENT\n"
            "  ----+----+-----+-------------------------------------------------\n",
            written);
        while (off + 2 <= written) {
            uint8_t  id  = dst[off];
            uint8_t  ilen = dst[off + 1];
            if (off + 2 + ilen > written)
                break;
            ++ie_num;
            if (id == 0) {
                char ssid_str[256] = {0};
                uint8_t slen = (ilen < 255) ? ilen : 254;
                memcpy(ssid_str, &dst[off + 2], slen);
                ssid_str[slen] = '\0';
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  SSID=\"%s\"\n", ie_num, id, ilen, ssid_str);
            } else if (id == 1) {
                char rbuf[256] = {0};
                int  rpos = 0;
                for (uint8_t r = 0; r < ilen && rpos < (int)sizeof(rbuf) - 8; r++) {
                    bool basic = (dst[off + 2 + r] & 0x80) != 0;
                    double mbps = (dst[off + 2 + r] & 0x7F) * 0.5;
                    rpos += snprintf(rbuf + rpos, sizeof(rbuf) - rpos,
                                     "%.1f%s%s", mbps,
                                     basic ? "*" : "",
                                     r + 1 < ilen ? " " : "");
                }
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  SupportedRates=[%s]\n", ie_num, id, ilen, rbuf);
            } else if (id == 45) {
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  HTCapabilities htcap_info=0x%02x%02x\n",
                    ie_num, id, ilen,
                    ilen >= 2 ? dst[off + 3] : 0,
                    ilen >= 1 ? dst[off + 2] : 0);
            } else if (id == 48) {
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  RSN\n", ie_num, id, ilen);
            } else if (id == 127) {
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  ExtendedCapabilities\n", ie_num, id, ilen);
            } else if (id == 191) {
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  VHTCapabilities\n", ie_num, id, ilen);
            } else if (id == 255) {
                uint8_t ext_id = (ilen >= 1) ? dst[off + 2] : 0;
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  ExtensionIE ext_id=%u%s\n",
                    ie_num, id, ilen, ext_id,
                    ext_id == 35 ? " (HE Capabilities)" : "");
            } else if (id == 221) {
                if (ilen >= 4) {
                    const uint8_t *d = &dst[off + 2];
                    char hbuf[128] = {0};
                    int  hpos = 0;
                    for (uint8_t b = 4; b < ilen && hpos < (int)sizeof(hbuf) - 4; b++) {
                        hpos += snprintf(hbuf + hpos, sizeof(hbuf) - hpos, "%02x ", d[b]);
                    }
                    wifi_util_dbg_print(WIFI_APPS,
                        "  %-3d  %-3u  %-4u  VendorSpecific OUI=%02x:%02x:%02x type=0x%02x data=[%s]\n",
                        ie_num, id, ilen, d[0], d[1], d[2], d[3], hbuf);
                } else {
                    wifi_util_dbg_print(WIFI_APPS,
                        "  %-3d  %-3u  %-4u  VendorSpecific (short len)\n", ie_num, id, ilen);
                }
            } else {
                wifi_util_dbg_print(WIFI_APPS,
                    "  %-3d  %-3u  %-4u  (raw)\n", ie_num, id, ilen);
            }
            off += 2 + ilen;
        }
        wifi_util_dbg_print(WIFI_APPS,
            "------------------------------------------------------------------\n");
    }

    return written;
}

/*
 * lq_fill_ap_mac_from_vap - populate ap_mac_str from the VAP's BSS info.
 *
 * Source: getVapInfo(vap_index)->u.bss_info.bssid.
 *
 * Used ONLY for Probe Request frames.  For all other management frame types
 * (Auth, Assoc REQ, Assoc RSP) the AP BSSID can be read directly from
 * bytes 16-21 of the 802.11 MAC header present in msg->data.  Probe REQ is
 * the exception because the 802.11 BSSID field in a probe request is set to
 * ff:ff:ff:ff:ff:ff (broadcast), so the frame itself cannot tell us which AP
 * received it — we must fall back to the VAP context.
 *
 * Returns true on success and fills out_ap_mac_str; returns false if
 * getVapInfo() returns NULL (should not happen on a running AP).
 */
static bool lq_fill_ap_mac_from_vap(unsigned int vap_index,
                                     mac_addr_str_t out_ap_mac_str)
{
    wifi_vap_info_t *vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d getVapInfo returned NULL for vap_index=%u — ap_mac_str not set\n",
            __func__, __LINE__, vap_index);
        return false;
    }
    to_mac_str(vap_info->u.bss_info.bssid, out_ap_mac_str);
    return true;
}

/*
 * Extract the 802.11 sequence number from the management frame header.
 * seq_ctrl (little-endian 16-bit): bits[15:4] = sequence number, bits[3:0] = fragment.
 * Sequence number wraps at LQ_SEQNUM_MAX (4096).
 */
static uint16_t lq_extract_seq_num(frame_data_t *msg)
{
    if (msg->frame.len < 24)
        return 0;
    const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)msg->data;
    uint16_t seq_ctrl = le_to_host16(mgmt->seq_ctrl);
    return (seq_ctrl >> 4) & 0x0FFF;
}

int link_quality_probe_req_event(wifi_app_t *app, void *arg)
{
    wifi_util_dbg_print(WIFI_APPS, "Enter %s:%d\n", __func__, __LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    frame_data_t *msg = (frame_data_t *)arg;

    stats_arg_t *affinity_arg = (stats_arg_t *)malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d unable to alloc memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(affinity_arg, 0, sizeof(stats_arg_t));
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);

    /* Filter: drop events except private VAPs (private_ssid*) */
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

    /*
     * Probe REQ: HAL receiver address is ff:ff:ff:ff:ff:ff (broadcast).
     * Use the VAP's BSS info to obtain the real AP BSSID.
     */
    if (lq_fill_ap_mac_from_vap(msg->frame.ap_index, affinity_arg->ap_mac_str)) {
        wifi_util_dbg_print(WIFI_APPS,
            "%s:%d PROBE_REQ ap_mac_str=%s (from VAP bss_info) STA=%s vap=%u\n",
            __func__, __LINE__, affinity_arg->ap_mac_str,
            affinity_arg->mac_str, affinity_arg->vap_index);
    }

    affinity_arg->frame_type = LQ_FRAME_TYPE_PROBE_REQ;
    affinity_arg->rssi = msg->frame.sig_dbm;
    affinity_arg->seq_number = lq_extract_seq_num(msg);
    clock_gettime(CLOCK_MONOTONIC, &affinity_arg->frame_timestamp);
    affinity_arg->event = wifi_event_hal_probe_req_frame;

    /*
     * IEs start at the 802.11 frame body — i.e., after the 24-byte MAC header
     * (offsetof(struct ieee80211_mgmt, u) == 24).  For a Probe REQ the body
     * contains IEs directly with no intervening fixed fields.
     * Parse only SSID, Supported Rates, and filtered Vendor IEs in
     * deterministic order.
     */
    {
        const unsigned int ie_offset = (unsigned int)offsetof(struct ieee80211_mgmt, u);
        if (msg->frame.len > ie_offset) {
            affinity_arg->ie_data_len = parse_and_store_ies(
                &msg->data[ie_offset], (uint16_t)(msg->frame.len - ie_offset),
                affinity_arg->ie_data, MAX_IE_DATA_LEN,
                affinity_arg->ie_order, MAX_IE_ORDER_LEN,
                &affinity_arg->vendor_ie_count);
            wifi_util_dbg_print(WIFI_APPS,
                "%s:%d Parsed %u bytes of IE data for PROBE_REQ MAC=%s ie_order=[%s] vendor_raw=%u\n",
                __func__, __LINE__, affinity_arg->ie_data_len, affinity_arg->mac_str,
                affinity_arg->ie_order, affinity_arg->vendor_ie_count);
        }
    }

    get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);

    free(affinity_arg);
    return RETURN_OK;
}

int link_quality_apps_auth_event(wifi_app_t *app, bool req, int sub_event,void *arg)
{
    stats_arg_t *affinity_arg = NULL;
    frame_data_t *msg = (frame_data_t *)arg;

    wifi_util_info_print(WIFI_APPS, "Enter %s:%d\n",__func__,__LINE__);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

   //Fill the affinity_arg with frame data 
    affinity_arg = (stats_arg_t *) malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memry\n",__func__,__LINE__);
       return RETURN_ERR;
    }

    memset(affinity_arg, 0, sizeof(stats_arg_t));
    
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);
    /* Filter: drop events except private VAPs (private_ssid*) */
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
    get_radio_channel_utilization(affinity_arg->radio_index,&affinity_arg->channel_utilization);
    affinity_arg->status_code = 0;
    affinity_arg->dev.cli_SNR = msg->frame.sig_dbm - NOISE_FLOOR;
    // dhcp_event = 0 (not a DHCP update) from memset
    wifi_util_info_print(WIFI_APPS," %s:%d auth client snr =%d\n",__func__,__LINE__,affinity_arg->dev.cli_SNR);
    

    // dhcp_event = 0 (not a DHCP update) from memset

    /*
     * msg->data holds the full 802.11 frame (MAC header + body).
     * 802.11 management MAC header layout (all frame types):
     *   bytes  0- 1: frame_control
     *   bytes  2- 3: duration
     *   bytes  4- 9: DA  (destination address)
     *   bytes 10-15: SA  (source address)
     *   bytes 16-21: BSSID  ← AP MAC for Auth (STA→AP direction)
     *   bytes 22-23: seq_ctrl
     *   bytes 24+  : frame-type-specific body
     *
     * BSSID is extracted directly from the 802.11 header. The minimum frame
     * size check (offsetof struct ieee80211_mgmt, u) == 24 bytes) covers it.
     */
    if (msg->frame.len >= (unsigned int)offsetof(struct ieee80211_mgmt, u)) {
        const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)msg->data;
        to_mac_str((unsigned char *)mgmt->bssid, affinity_arg->ap_mac_str);
        wifi_util_dbg_print(WIFI_APPS,
            "%s:%d AUTH ap_mac_str=%s (from 802.11 header BSSID) STA=%s vap=%u\n",
            __func__, __LINE__, affinity_arg->ap_mac_str,
            affinity_arg->mac_str, affinity_arg->vap_index);
    } else {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d AUTH frame too short (len=%u) to read BSSID — ap_mac_str left empty\n",
            __func__, __LINE__, msg->frame.len);
    }

    /* Classify auth frame type: SEQ1 vs other.
     * Auth frame body starts at byte 24 (after the 802.11 MAC header):
     *   bytes 24-25: auth_alg
     *   bytes 26-27: auth_transaction  ← this is the "sequence number" (1, 2, 3...)
     *   bytes 28-29: status_code
     * NOTE: do NOT use msg->data[2]/[3] — those are the duration field. */
    affinity_arg->frame_type = LQ_FRAME_TYPE_AUTH;
    if (msg->frame.len >= (unsigned int)(offsetof(struct ieee80211_mgmt, u) + 4)) {
        const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)msg->data;
        uint16_t auth_seq_number = le_to_host16(mgmt->u.auth.auth_transaction);
        wifi_util_info_print(WIFI_APPS, "%s:%d AUTH frame auth_seq=%u MAC=%s\n",
            __func__, __LINE__, auth_seq_number, affinity_arg->mac_str);
        if (auth_seq_number == 1) {
            affinity_arg->frame_type = LQ_FRAME_TYPE_AUTH_SEQ1;
        }
    }

    affinity_arg->rssi = msg->frame.sig_dbm;
    affinity_arg->seq_number = lq_extract_seq_num(msg);
    clock_gettime(CLOCK_MONOTONIC, &affinity_arg->frame_timestamp);
    /* Do NOT copy IE data for auth frames */
    affinity_arg->ie_data_len = 0;
    if (req)   {
        affinity_arg->event = sub_event;
        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
    }

    free(affinity_arg);
    return RETURN_OK;
}

int link_quality_apps_assoc_event(wifi_app_t *app, bool req,int sub_event,void *arg)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d sub_event=%d req=%d\n",__func__,__LINE__, sub_event, req);
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
   //Fill the affinity_arg with frame data 
    stats_arg_t *affinity_arg = (stats_arg_t *) malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memry\n",__func__,__LINE__);
       return RETURN_ERR;
    }
    memset(affinity_arg, 0, sizeof(stats_arg_t));
    frame_data_t *msg = (frame_data_t *)arg;
    
    // Populate MAC address from frame
    to_mac_str(msg->frame.sta_mac, affinity_arg->mac_str);
    affinity_arg->vap_index = msg->frame.ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);
    affinity_arg->dev.cli_SNR = msg->frame.sig_dbm - NOISE_FLOOR;
    wifi_util_info_print(WIFI_APPS," %s:%d assoc client snr =%d\n",__func__,__LINE__,affinity_arg->dev.cli_SNR);
    
    // dhcp_event = 0 (not a DHCP update) from memset
    if (req)   {
        affinity_arg->event = sub_event;
    /* Filter: drop events except private VAPs (private_ssid*) */
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

    /*
     * Extract AP BSSID from bytes 16-21 of the 802.11 MAC header embedded in
     * msg->data (the full frame, MAC header + body, is always present).
     *
     * 802.11 management MAC header layout:
     *   bytes  4- 9: DA     (destination)
     *   bytes 10-15: SA     (source = STA MAC for REQ, AP MAC for RSP)
     *   bytes 16-21: BSSID  (AP MAC for both REQ and RSP directions)
     *
     * This applies to Assoc REQ (STA→AP) and Assoc RSP (AP→STA) alike;
     * the BSSID field always contains the AP address regardless of direction.
     */
    if (msg->frame.len >= (unsigned int)offsetof(struct ieee80211_mgmt, u)) {
        const struct ieee80211_mgmt *mgmt80211 = (const struct ieee80211_mgmt *)msg->data;
        to_mac_str((unsigned char *)mgmt80211->bssid, affinity_arg->ap_mac_str);
        wifi_util_dbg_print(WIFI_APPS,
            "%s:%d ASSOC ap_mac_str=%s (from 802.11 header BSSID) STA=%s vap=%u sub_event=%d\n",
            __func__, __LINE__, affinity_arg->ap_mac_str,
            affinity_arg->mac_str, affinity_arg->vap_index, sub_event);
    } else {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d ASSOC frame too short (len=%u) to read BSSID — ap_mac_str left empty\n",
            __func__, __LINE__, msg->frame.len);
    }

    /* Populate frame metadata */
    affinity_arg->rssi = msg->frame.sig_dbm;
    affinity_arg->seq_number = lq_extract_seq_num(msg);
    clock_gettime(CLOCK_MONOTONIC, &affinity_arg->frame_timestamp);

    // dhcp_event = 0 (not a DHCP update) from memset
    if (req)   {
        affinity_arg->event = sub_event;

        /* Classify frame type and copy IEs for assoc/reassoc requests */
        if ((sub_event == wifi_event_hal_assoc_req_frame) || (sub_event == wifi_event_hal_reassoc_req_frame)) {
            affinity_arg->frame_type = LQ_FRAME_TYPE_ASSOC_REQ;

            /*
             * IEs start after the 802.11 MAC header (24 bytes) + the
             * fixed-length frame body fields:
             *   Assoc REQ:   24 (hdr) + 2 (capab) + 2 (listen_interval) = 28
             *   Reassoc REQ: 24 (hdr) + 2 (capab) + 2 (listen_interval)
             *                        + 6 (current_ap)                    = 34
             * Parse only SSID, Supported Rates, and filtered Vendor IEs
             * in deterministic order.
             */
            unsigned int ie_offset = (sub_event == wifi_event_hal_reassoc_req_frame) ? 34 : 28;
            if (msg->frame.len > ie_offset) {
                affinity_arg->ie_data_len = parse_and_store_ies(
                    &msg->data[ie_offset],
                    (uint16_t)(msg->frame.len - ie_offset),
                    affinity_arg->ie_data, MAX_IE_DATA_LEN,
                    affinity_arg->ie_order, MAX_IE_ORDER_LEN,
                    &affinity_arg->vendor_ie_count);
                wifi_util_dbg_print(WIFI_APPS,
                    "%s:%d Parsed %u bytes of IE data for ASSOC_REQ MAC=%s ie_order=[%s] vendor_raw=%u\n",
                    __func__, __LINE__, affinity_arg->ie_data_len, affinity_arg->mac_str,
                    affinity_arg->ie_order, affinity_arg->vendor_ie_count);
            }
        }
        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
    } else {
        // Check sub_event for wifi_event_hal_assoc_rsp_frame OR wifi_event_hal_reassoc_rsp_frame
        if ((sub_event == wifi_event_hal_assoc_rsp_frame) || (sub_event == wifi_event_hal_reassoc_rsp_frame)) {
            /*
             * Cast msg->data (not &msg->data) to ieee80211_mgmt*.  Both forms
             * resolve to the same address, but msg->data is the correct idiom
             * for an embedded array field.
             * ap_mac_str was already set from mgmt80211->bssid above (shared
             * with the REQ path).  Log it unconditionally so it is visible for
             * both success and failure cases.
             */
            const struct ieee80211_mgmt *frame = (const struct ieee80211_mgmt *)msg->data;
            uint16_t status = le_to_host16(frame->u.assoc_resp.status_code);
            wifi_util_info_print(WIFI_CTRL,
                "%s:%d ASSOC RSP status=%u ap_mac_str=%s STA=%s (BSSID from 802.11 header)\n",
                __func__, __LINE__, status,
                affinity_arg->ap_mac_str, affinity_arg->mac_str);
            if (status != 0) {
                wifi_util_error_print(WIFI_CTRL,
                    "CAFF %s:%d ASSOC FAILURE MAC=%s sub_event=%d status_code=%u vap=%u radio=%u\n",
                    __func__, __LINE__, affinity_arg->mac_str, sub_event, status,
                    affinity_arg->vap_index, affinity_arg->radio_index);
            }
            affinity_arg->event = sub_event;
            affinity_arg->status_code = status;
            affinity_arg->frame_type = LQ_FRAME_TYPE_ASSOC_RES;
            affinity_arg->ie_data_len = 0;
            affinity_arg->dev.cli_SNR = msg->frame.sig_dbm - NOISE_FLOOR;
            affinity_arg->vap_index = msg->frame.ap_index;
            affinity_arg->radio_index = getRadioIndexFromAp(msg->frame.ap_index);

            // if Status is success add AP mac address into stats_arg_t
            if (status == 0) {
                wifi_vap_info_t *vap_info = NULL;
                vap_info = getVapInfo(msg->frame.ap_index);
                if (vap_info != NULL) {
                    to_mac_str(vap_info->u.bss_info.bssid, affinity_arg->ap_mac_str);
                    wifi_util_info_print(WIFI_CTRL," RMS %s:%d AP BSSID: %s for STA: %s\n",
                        __func__, __LINE__, affinity_arg->ap_mac_str, affinity_arg->mac_str);
                }

            }
            wifi_util_info_print(WIFI_CTRL, " %s:%d Calling get_lq_descriptor()->periodic_caffinity_stats_update_fn for MAC %s, event=%d, status=%d\n snr = %d",
                __func__, __LINE__, affinity_arg->mac_str, sub_event, status,affinity_arg->dev.cli_SNR);
            get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg,1);
        } else if (sub_event == wifi_event_hal_sta_conn_status) {
            affinity_arg->event = sub_event;
            wifi_util_info_print(WIFI_CTRL, "%s:%d Sending sta_conn_status to WEI for MAC %s snr=%d\n",
                __func__, __LINE__, affinity_arg->mac_str, affinity_arg->dev.cli_SNR);
            get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg, 1);
        }
    }
    free(affinity_arg);
    return RETURN_OK;
}
int link_quality_apps_disassoc_event(wifi_app_t *app, bool req,int sub_event,void *arg)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    
    /* The disassoc_device event carries assoc_dev_data_t (the same type the
     * motion/whix/sensing apps consume), NOT frame_data_t. It includes the
     * driver-provided 802.11 disconnect reason, which WEI uses to distinguish an
     * EAPOL/auth failure (wrong password, RADIUS reject, ...) from a clean leave. */
    assoc_dev_data_t *msg = (assoc_dev_data_t *)arg;
    
    // Fill the affinity_arg with disassoc data 
    stats_arg_t *affinity_arg = (stats_arg_t *) malloc(sizeof(stats_arg_t));
    if (affinity_arg == NULL) {
        wifi_util_info_print(WIFI_APPS," %s:%d unable to alloc memory\n",__func__,__LINE__);
        return RETURN_ERR;
    }
    
    memset(affinity_arg, 0, sizeof(stats_arg_t));
    to_mac_str(msg->dev_stats.cli_MACAddress, affinity_arg->mac_str);
    affinity_arg->vap_index = msg->ap_index;
    affinity_arg->radio_index = getRadioIndexFromAp(msg->ap_index);
    get_radio_channel_utilization(affinity_arg->radio_index, &affinity_arg->channel_utilization);
    /* Carry the 802.11 disconnect reason in status_code for WEI to classify. */
    affinity_arg->status_code = msg->reason;
    if (req) {
        affinity_arg->event = sub_event;
        get_lq_descriptor()->periodic_caffinity_stats_update_fn(affinity_arg,1);
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
            link_quality_apps_assoc_event(apps,false,sub_type,arg);
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
            link_quality_apps_disassoc_event(apps,true,sub_type,arg);
            break;
        case wifi_event_hal_probe_req_frame:
            wifi_util_dbg_print(WIFI_APPS, " %s:%d probe event = %d\n", __func__, __LINE__, sub_type);
            link_quality_probe_req_event(apps, arg);
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
            link_quality_apps_assoc_event(apps,false,sub_type,arg);
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
            link_quality_apps_disassoc_event(apps,true,sub_type,arg);
            break;
        
        default:
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

int link_quality_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_rfc_dml_parameters_t *rfc_param = NULL;
    rfc_param = get_ctrl_rfc_parameters();
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            exec_event_webconfig_event(app, event);
            break;

        case wifi_event_type_exec:
            exec_event_link_quality(app, event->sub_type, event->u.core_data.msg, event->u.core_data.len);
            break;

        case wifi_event_type_hal_ind:

            if ((rfc_param->wei_rfc_mask & WEI_RFC_SC) || (rfc_param->wei_rfc_mask & WEI_RFC_GC))
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
