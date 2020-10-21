/* Copyright (c) 2020 Wi-Fi Alliance                                                */
/* Permission to a personal, non-exclusive, non-transferable use of this            */
/* software in object code form only, solely for the purposes of supporting         */
/* Wi-Fi certification program development, Wi-Fi pre-certification testing,        */
/* and formal Wi-Fi certification testing by authorized test labs, Wi-Fi            */
/* Alliance members in good standing and their customers, provided that any         */
/* part of this software shall not be copied or reproduced in any way. Wi-Fi        */
/* Alliance Software License Agreement governing this software can be found at      */
/* https://www.wi-fi.org/file/wi-fi-alliance-software-end-user-license-agreement.   */
/* The foregoing license shall terminate if Customer breaches any term hereof       */
/* and fails to cure such breach within five (5) days of notice of breach.          */

/* THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL                    */
/* WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                    */
/* WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL                     */
/* THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                       */
/* CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING                        */
/* FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF                       */
/* CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT                       */
/* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS                          */
/* SOFTWARE. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "indigo_api.h"
#include "utils.h"

struct indigo_api indigo_api_list[] = {
    { API_CMD_RESPONSE, "CMD_RESPONSE", NULL, NULL },
    { API_CMD_ACK, "CMD_ACK", NULL, NULL },

    { API_AP_START_UP, "AP_START_UP", NULL, NULL },
    { API_AP_STOP, "AP_STOP", NULL, NULL },
    { API_AP_CONFIGURE, "AP_CONFIGURE", NULL, NULL },
    { API_AP_TRIGGER_CHANSWITCH, "AP_TRIGGER_CHANSWITCH", NULL, NULL },
    { API_AP_SEND_DISCONNECT, "AP_SEND_DISCONNECT", NULL, NULL },
    { API_AP_SET_PARAM, "API_AP_SET_PARAM", NULL, NULL },
    { API_AP_SEND_BTM_REQ, "API_AP_SEND_BTM_REQ", NULL, NULL },

    { API_STA_ASSOCIATE, "STA_ASSOCIATE", NULL, NULL },
    { API_STA_CONFIGURE, "STA_CONFIGURE", NULL, NULL },
    { API_STA_DISCONNECT, "STA_DISCONNECT", NULL, NULL },
    { API_STA_SEND_DISCONNECT, "STA_SEND_DISCONNECT", NULL, NULL },
    { API_STA_REASSOCIATE, "STA_REASSOCIATE", NULL, NULL },
    { API_STA_SET_PARAM, "STA_SET_PARAM", NULL, NULL },
    { API_STA_SEND_BTM_QUERY, "STA_SEND_BTM_QUERY", NULL, NULL },
    { API_STA_SEND_ANQP_QUERY, "STA_SEND_ANQP_QUERY", NULL, NULL },

    { API_GET_IP_ADDR, "GET_IP_ADDR", NULL, NULL },
    { API_GET_MAC_ADDR, "GET_MAC_ADDR", NULL, NULL },
    { API_GET_CONTROL_APP_VERSION, "GET_CONTROL_APP_VERSION", NULL, NULL },
    { API_INDIGO_START_LOOP_BACK_SERVER, "INDIGO_START_LOOP_BACK_SERVER", NULL, NULL },
    { API_INDIGO_STOP_LOOP_BACK_SERVER, "INDIGO_STOP_LOOP_BACK_SERVER", NULL, NULL },
    { API_CREATE_NEW_INTERFACE_BRIDGE_NETWORK, "CREATE_NEW_INTERFACE_BRIDGE_NETWORK", NULL, NULL },
    { API_ASSIGN_STATIC_IP, "ASSIGN_STATIC_IP", NULL, NULL },
    { API_DEVICE_RESET, "DEVICE_RESET", NULL, NULL },
};

struct indigo_tlv indigo_tlv_list[] = {
    { TLV_SSID, "SSID" },
    { TLV_CHANNEL, "CHANNEL" },
    { TLV_WEP_KEY0, "WEP_KEY0" },
    { TLV_AUTH_ALGORITHM, "AUTH_ALGORITHM" },
    { TLV_WEP_DEFAULT_KEY, "WEP_DEFAULT_KEY" },
    { TLV_IEEE80211_D, "IEEE80211_D" },
    { TLV_IEEE80211_N, "IEEE80211_N" },
    { TLV_IEEE80211_AC, "IEEE80211_AC" },
    { TLV_COUNTRY_CODE, "COUNTRY_CODE" },
    { TLV_WMM_ENABLED, "WMM_ENABLED" },
    { TLV_WPA, "WPA" },
    { TLV_WPA_KEY_MGMT, "WPA_KEY_MGMT" },
    { TLV_RSN_PAIRWISE, "RSN_PAIRWISE" },
    { TLV_WPA_PASSPHRASE, "WPA_PASSPHRASE" },
    { TLV_WPA_PAIRWISE, "WPA_PAIRWISE" },
    { TLV_HT_CAPB, "HT_CAPB" },
    { TLV_IEEE80211_H, "IEEE80211_H" },
    { TLV_IEEE80211_W, "IEEE80211_W" },
    { TLV_VHT_OPER_CHWIDTH, "VHT_OPER_CHWIDTH" },
    { TLV_VHT_OPER_CENTR_REQ, "VHT_OPER_CENTR_REQ" },
    { TLV_IEEE8021_X, "IEEE8021_X" },
    { TLV_EAP_SERVER, "EAP_SERVER" },
    { TLV_AUTH_SERVER_ADDR, "AUTH_SERVER_ADDR" },
    { TLV_AUTH_SERVER_PORT, "AUTH_SERVER_PORT" },
    { TLV_AUTH_SERVER_SHARED_SECRET, "AUTH_SERVER_SHARED_SECRET" },
    { TLV_INTERFACE_NAME, "INTERFACE_NAME" },
    { TLV_NEW_INTERFACE_NAME, "NEW_INTERFACE_NAME" },
    { TLV_FREQUENCY, "FREQUENCY" },
    { TLV_BSS_IDENTIFIER, "BSS_IDENTIFIER" },
    { TLV_HW_MODE, "HW_MODE" },
    { TLV_VHT_OPER_CENTR_FREQ, "VHT_OPER_CENTR_FREQ" },
    { TLV_EAPOL_KEY_INDEX_WORKAROUND, "EAPOL_KEY_INDEX_WORKAROUND" },
    { TLV_LOGGER_SYSLOG, "LOGGER_SYSLOG" },
    { TLV_LOGGER_SYSLOG_LEVEL, "LOGGER_SYSLOG_LEVEL" },
    { TLV_IE_OVERRIDE, "IE_OVERRIDE" },
    { TLV_RECONFIG, "RECONFIG" },
    { TLV_SAME_ANONCE, "SAME_ANONCE" },
    { TLV_INTERFACE, "INTERFACE" },
    { TLV_FRAME_TYPE, "FRAME_TYPE" },
    { TLV_ADDRESS, "ADDRESS" },
    { TLV_REASON, "REASON" },
    { TLV_TEST, "TEST" },
    { TLV_VENDOR_ELEMENTS, "VENDOR_ELEMENTS" },
    { TLV_ASSOCRESP_ELEMENTS, "ASSOCRESP_ELEMENTS" },
    { TLV_SOURCE_ADDRESS, "SOURCE_ADDRESS" },
    { TLV_FRAME_CONTROL, "FRAME_CONTROL" },
    { TLV_TIMEOUT, "TIMEOUT" },
    { TLV_EVENT, "EVENT" },
    { TLV_CLEAR, "CLEAR" },
    { TLV_SAE_COMMIT_OVERRIDE, "SAE_COMMIT_OVERRIDE" },
    { TLV_DISABLE_PMKSA_CACHING, "DISABLE_PMKSA_CACHING" },
    { TLV_SAE_ANTI_CLOGGING_THRESHOLD, "SAE_ANTI_CLOGGING_THRESHOLD" },
    { TLV_STA_SSID, "STA_SSID" },
    { TLV_KEY_MGMT, "KEY_MGMT" },
    { TLV_STA_WEP_KEY0, "STA_WEP_KEY0" },
    { TLV_WEP_TX_KEYIDX, "WEP_TX_KEYIDX" },
    { TLV_GROUP, "GROUP" },
    { TLV_PSK, "PSK" },
    { TLV_PROTO, "PROTO" },
    { TLV_STA_IEEE80211_W, "STA_IEEE80211_W" },
    { TLV_PAIRWISE, "PAIRWISE" },
    { TLV_EAP, "EAP" },
    { TLV_PHASE2, "PHASE2" },
    { TLV_IDENTITY, "IDENTITY" },
    { TLV_PASSWORD, "PASSWORD" },
    { TLV_CA_CERT, "CA_CERT" },
    { TLV_PHASE1, "PHASE1" },
    { TLV_CLIENT_CERT, "CLIENT_CERT" },
    { TLV_PRIVATE_KEY, "PRIVATE_KEY" },
    { TLV_STA_IE_OVERRIDE, "STA_IE_OVERRIDE" },
    { TLV_STA_MAC_ADDRESS, "STA_MAC_ADDRESS" },
    { TLV_STA_CLEAR, "STA_CLEAR" },
    { TLV_STA_TIMEOUT, "STA_TIMEOUT" },
    { TLV_STA_EVENT, "STA_EVENT" },
    { TLV_STA_LOCALLY_GENERATED, "STA_LOCALLY_GENERATED" },
    { TLV_FREQ, "FREQ" },
    { TLV_FORCE_SCAN, "FORCE_SCAN" },
    { TLV_PASSIVE, "PASSIVE" },
    { TLV_STA_COMMIT_OVERRIDE, "STA_COMMIT_OVERRIDE" },
    { TLV_AP_MAC_ADDRESS, "AP_MAC_ADDRESS" },
    { TLV_SAE_RECONNECT, "SAE_RECONNECT" },
    { TLV_STA_POWER_SAVE, "STA_POWER_SAVE" },
    { TLV_TOOL_IP_ADDRESS, "TOOL_IP_ADDRESS" },
    { TLV_TOOL_UDP_PORT, "TOOL_UDP_PORT" },
    { TLV_STATIC_IP, "STATIC_IP" },
    { TLV_DEVICE_ROLE, "DEVICE_ROLE" },
    { TLV_DEBUG_LEVEL, "DEBUG_LEVEL" },
    { TLV_DUT_IP_ADDRESS, "DUT_IP_ADDRESS" },
    { TLV_HOSTAPD_FILE_NAME, "HOSTAPD_FILE_NAME" },
    { TLV_DUT_TYPE, "DUT_TYPE" },
    { TLV_CONCURRENT_HOSTAPD_FILE, "CONCURRENT_HOSTAPD_FILE" },
    { TLV_ROLE, "ROLE" },
    { TLV_BAND, "BAND" },
    { TLV_BSSID, "BSSID" },
    { TLV_ARP_TRANSMISSION_RATE, "ARP_TRANSMISSION_RATE" },
    { TLV_ARP_TARGET_IP, "ARP_TARGET_IP" },
    { TLV_ARP_TARGET_MAC, "ARP_TARGET_MAC" },
    { TLV_ARP_FRAME_COUNT, "ARP_FRAME_COUNT" },
    { TLV_CHANGE_ANONCE, "CHANGE_ANONCE" },
    { TLV_USE_PLAIN_TEXT, "USE_PLAIN_TEXT" },
    { TLV_REPEAT_M3_FRAMES, "REPEAT_M3_FRAMES" },
    { TLV_M3_FRAME_REPEAT_RATE, "M3_FRAME_REPEAT_RATE" },
    { TLV_PACKET_COUNT, "PACKET_COUNT" },
    { TLV_SEND_M1_FRAMES, "SEND_M1_FRAMES" },
    { TLV_UDP_PACKET_RATE, "UDP_PACKET_RATE" },
    { TLV_PHYMODE, "PHYMODE" },
    { TLV_CHANNEL_WIDTH, "CHANNEL_WIDTH" },
    { TLV_WMM_MODE, "WMM_MODE" },
    { TLV_PAC_FILE, "PAC_FILE" },
    { TLV_STA_SAE_GROUPS, "STA_SAE_GROUPS" },
    { TLV_BROADCAST_ADDR, "BROADCAST_ADDR" },
    { TLV_START_IMMEDIATE_M3, "START_IMMEDIATE_M3" },
    { TLV_SAE_GROUPS, "SAE_GROUPS" },
    { TLV_IEEE80211_AX, "IEEE80211_AX" },
    { TLV_HE_OPER_CHWIDTH, "HE_OPER_CHWIDTH" },
    { TLV_HE_OPER_CENTR_FREQ, "HE_OPER_CENTR_FREQ" },
    { TLV_MBO, "MBO" },
    { TLV_MBO_CELL_DATA_CONN_PREF, "MBO_CELL_DATA_CONN_PREF" },
    { TLV_BSS_TRANSITION, "BSS_TRANSITION" },
    { TLV_INTERWORKING, "INTERWORKING" },
    { TLV_RRM_NEIGHBOR_REPORT, "RRM_NEIGHBOR_REPORT" },
    { TLV_RRM_BEACON_REPORT, "RRM_BEACON_REPORT" },
    { TLV_COUNTRY3, "COUNTRY3" },
    { TLV_MBO_CELL_CAPA, "MBO_CELL_CAPA" },
    { TLV_DOMAIN_MATCH, "TLV_DOMAIN_MATCH" },
    { TLV_DOMAIN_SUFFIX_MATCH, "TLV_DOMAIN_SUFFIX_MATCH" },
    { TLV_MBO_ASSOC_DISALLOW, "TLV_MBO_ASSOC_DISALLOW" },
    { TLV_MBO_IGNORE_ASSOC_DISALLOW, "TLV_MBO_IGNORE_ASSOC_DISALLOW" },
    { TLV_DISASSOC_IMMINENT, "TLV_DISASSOC_IMMINENT" },
    { TLV_BSS_TERMINATION, "TLV_BSS_TERMINATION" },
    { TLV_DISASSOC_TIMER, "TLV_DISASSOC_TIMER" },
    { TLV_BSS_TERMINATION_TSF, "TLV_BSS_TERMINATION_TSF" },
    { TLV_BSS_TERMINATION_DURATION, "TLV_BSS_TERMINATION_DURATION" },
    { TLV_REASSOCIAITION_RETRY_DELAY, "TLV_REASSOCIAITION_RETRY_DELAY" },
    { TLV_BTMQUERY_REASON_CODE, "TLV_BTMQUERY_REASON_CODE" },
    { TLV_CANDIDATE_LIST, "TLV_CANDIDATE_LIST" },
    { TLV_ANQP_INFO_ID, "TLV_ANQP_INFO_ID" },
    { TLV_GAS_COMEBACK_DELAY, "TLV_GAS_COMEBACK_DELAY" },
    { TLV_SAE_PWE, "TLV_SAE_PWE" },
    { TLV_OWE_GROUPS, "TLV_OWE_GROUPS" },
    { TLV_STA_OWE_GROUP, "TLV_STA_OWE_GROUP" },
    { TLV_HE_MU_EDCA, "TLV_HE_MU_EDCA" },
    { TLV_SAE_PMKID_IN_ASSOC, "TLV_SAE_PMKID_IN_ASSOC" },
    { TLV_RSNXE_OVERRIDE_EAPOL, "RSNXE_OVERRIDE_EAPOL" },
    { TLV_TRANSITION_DISABLE, "TRANSITION_DISABLE" },
    { TLV_MESSAGE, "MESSAGE" },
    { TLV_STATUS, "STATUS" },
    { TLV_DUT_WLAN_IP_ADDR, "DUT_WLAN_IP_ADDR" },
    { TLV_DUT_MAC_ADDR, "DUT_MAC_ADDR" },
    { TLV_CONTROL_APP_VERSION, "CONTROL_APP_VERSION" },
};

char* get_api_type_by_id(int id) {
    int i = 0;
    for (i = 0; i < sizeof(indigo_api_list)/sizeof(struct indigo_api); i++) {
        if (id == indigo_api_list[i].type) {
            return indigo_api_list[i].name;
        }
    }
    return "Unknown";
}

struct indigo_api* get_api_by_id(int id) {
    int i = 0;
    for (i = 0; i < sizeof(indigo_api_list)/sizeof(struct indigo_api); i++) {
        if (id == indigo_api_list[i].type) {
            return &indigo_api_list[i];
        }
    }
    return NULL;
}

struct indigo_tlv* get_tlv_by_id(int id) {
    int i = 0;

    for (i = 0; i < sizeof(indigo_tlv_list)/sizeof(struct indigo_tlv); i++) {
        if (id == indigo_tlv_list[i].id) {
            return &indigo_tlv_list[i];
        }
    }
    return NULL;
}


// Other file
/* status: 0 - ACK, 1 - NACK */
void fill_wrapper_ack(struct packet_wrapper *wrapper, int seq, int status, char *reason) {
    wrapper->hdr.version = API_VERSION;
    wrapper->hdr.type = API_CMD_ACK;
    wrapper->hdr.seq = seq;
    wrapper->hdr.reserved = API_RESERVED_BYTE;
    wrapper->hdr.reserved2 = API_RESERVED_BYTE;

    wrapper->tlv_num =  2;
    wrapper->tlv[0] = malloc(sizeof(struct tlv_hdr));
    wrapper->tlv[0]->id = TLV_STATUS;
    wrapper->tlv[0]->len = 1;
    wrapper->tlv[0]->value = (char*)malloc(wrapper->tlv[0]->len);
    wrapper->tlv[0]->value[0] = status;

    wrapper->tlv[1] = malloc(sizeof(struct tlv_hdr));
    wrapper->tlv[1]->id = TLV_MESSAGE;
    wrapper->tlv[1]->len = strlen(reason);
    wrapper->tlv[1]->value = (char*)malloc(wrapper->tlv[1]->len);
    memcpy(wrapper->tlv[1]->value, reason, wrapper->tlv[1]->len);
}

void register_api(int id, api_callback_func verify, api_callback_func handle) {
    struct indigo_api *api;
    api = get_api_by_id(id);
    if (api) {
        api->verify = verify;
        api->handle = handle;
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to find the API 0x%04x", id);
    }
}

void fill_wrapper_message_hdr(struct packet_wrapper *wrapper, int msg_type, int seq) {
    wrapper->hdr.version = API_VERSION;
    wrapper->hdr.type = msg_type;
    wrapper->hdr.seq = seq;
    wrapper->hdr.reserved = API_RESERVED_BYTE;
    wrapper->hdr.reserved2 = API_RESERVED_BYTE;
}

void fill_wrapper_tlv_byte(struct packet_wrapper *wrapper, int id, char value) {
    wrapper->tlv[wrapper->tlv_num] = malloc(sizeof(struct tlv_hdr));
    wrapper->tlv[wrapper->tlv_num]->id = id;
    wrapper->tlv[wrapper->tlv_num]->len = 1;
    wrapper->tlv[wrapper->tlv_num]->value = (char*)malloc(1);
    wrapper->tlv[wrapper->tlv_num]->value[0] = value;
    wrapper->tlv_num++;
}

void fill_wrapper_tlv_bytes(struct packet_wrapper *wrapper, int id, int len, char* value) {
    wrapper->tlv[wrapper->tlv_num] = malloc(sizeof(struct tlv_hdr));
    wrapper->tlv[wrapper->tlv_num]->id = id;
    wrapper->tlv[wrapper->tlv_num]->len = len;
    wrapper->tlv[wrapper->tlv_num]->value = (char*)malloc(len);
    memcpy(wrapper->tlv[wrapper->tlv_num]->value, value, len);
    wrapper->tlv_num++;
}
