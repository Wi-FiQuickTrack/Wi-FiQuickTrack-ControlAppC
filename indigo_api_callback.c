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
#include <unistd.h>

#include "indigo_api.h"
#include "utils.h"

int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int stop_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int stop_loop_back_server_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int configure_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int start_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int assign_static_ip_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int get_mac_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
int start_loopback_server(struct packet_wrapper *req, struct packet_wrapper *resp);

void register_apis() {
    register_api(API_GET_CONTROL_APP_VERSION, NULL, get_control_app_handler);
    register_api(API_INDIGO_START_LOOP_BACK_SERVER, NULL, start_loopback_server);
    register_api(API_INDIGO_STOP_LOOP_BACK_SERVER, NULL, stop_loop_back_server_handler);
    register_api(API_AP_STOP, NULL, stop_ap_handler);
    register_api(API_AP_CONFIGURE, NULL, configure_ap_handler);
    register_api(API_AP_START_UP, NULL, start_ap_handler);
    register_api(API_ASSIGN_STATIC_IP, NULL, assign_static_ip_handler);
    register_api(API_GET_MAC_ADDR, NULL, get_mac_addr_handler);
}

/* TODO: Move to another file */
#define TLV_VALUE_APP_VERSION                       "v1.0"
#define TLV_VALUE_OK                                "OK"
#define TLV_VALUE_STATUS_OK                         0x30
#define TLV_VALUE_STATUS_NOT_OK                     0x31
#define TLV_VALUE_LOOP_BACK_STOP_OK                 "Loopback server in idle state"
#define TLV_VALUE_HOSTAPD_STOP_OK                   "AP stop completed : Hostapd service is inactive."
#define TLV_VALUE_HOSTAPD_STOP_NOT_OK               "Unable to stop hostapd service."
#define TLV_VALUE_HOSTAPD_START_OK                  "AP is up : Hostapd service is active"
#define TLV_VALUE_ASSIGN_STATIC_IP_OK               "Static IP successfully assigned to wireless interface"
#define TLV_VALUE_ASSIGN_STATIC_IP_NOT_OK           "Static IP failed to be assigned to wireless interface"
#define TLV_VALUE_LOOPBACK_SVR_START_OK             "Loop back server initialized"
#define TLV_VALUE_LOOPBACK_SVR_START_NOT_OK         "Failed to initialise loop back server"

int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_OK), TLV_VALUE_OK);
    fill_wrapper_tlv_bytes(resp, TLV_CONTROL_APP_VERSION, strlen(TLV_VALUE_APP_VERSION), TLV_VALUE_APP_VERSION);
    return 0;
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'AP stop completed : Hostapd service is inactive.'} 
int stop_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[10240];
    char *parameter[] = {"pidof", "hostapd", NULL};
    char *message = NULL;

    memset(buffer, 0, sizeof(buffer));

    len = system("killall hostapd 1>/dev/null 2>/dev/null");
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to stop hostapd");
    }
    sleep(2);

    len = system("rm -rf /etc/hostapd/*.conf");
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove hostapd.conf");
    }
    sleep(1);

    len = system("rfkill unblock wlan");
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to run rfkill unblock wlan");
    }
    sleep(1);

    len = pipe_command(buffer, sizeof(buffer), "/bin/pidof", parameter);
    if (len) {
        message = TLV_VALUE_HOSTAPD_STOP_NOT_OK;
    } else {
        message = TLV_VALUE_HOSTAPD_STOP_OK;
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
   
    return 0;
}

struct hostapd_tlv_to_config_name {
    unsigned short tlv_id;
    char config_name[NAME_SIZE];
};
#define DEFAULT_INTERFACE_NAME          "wlan0"

int generate_hostapd_config(char *buffer, int buffer_size, struct packet_wrapper *wrapper) {
    struct hostapd_tlv_to_config_name maps[] = {
        { TLV_SSID, "ssid" },
        { TLV_CHANNEL, "channel" },
        { TLV_WEP_KEY0, "wep_key0" },
        { TLV_HW_MODE, "hw_mode" },
        { TLV_AUTH_ALGORITHM, "auth_algs" },
        { TLV_WEP_DEFAULT_KEY, "wep_default_key" },
        { TLV_IEEE80211_D, "ieee80211d" },
        { TLV_IEEE80211_N, "ieee80211n" },
        { TLV_IEEE80211_AC, "ieee80211ac" },
        { TLV_COUNTRY_CODE, "country_code" },
        { TLV_WMM_ENABLED, "wmm_enabled" },
        { TLV_WPA, "wpa" },
        { TLV_WPA_KEY_MGMT, "wpa_key_mgmt" },
        { TLV_RSN_PAIRWISE, "rsn_pairwise" },
        { TLV_WPA_PASSPHRASE, "wpa_passphrase" },
        { TLV_WPA_PAIRWISE, "wpa_pairwise" },
        { TLV_HT_CAPB, "ht_capab" },
        { TLV_IEEE80211_W, "ieee80211w" },
        { TLV_IEEE80211_H, "ieee80211h" },
        { TLV_VHT_OPER_CHWIDTH, "vht_oper_chwidth" },
        { TLV_VHT_OPER_CENTR_REQ, "vht_oper_centr_freq_seg0_idx" },
        { TLV_EAP_SERVER, "eap_server" },
        { TLV_EAPOL_KEY_INDEX_WORKAROUND, "eapol_key_index_workaround" },
        { TLV_AUTH_SERVER_ADDR, "auth_server_addr" },
        { TLV_AUTH_SERVER_PORT, "auth_server_port" },
        { TLV_AUTH_SERVER_SHARED_SECRET, "auth_server_shared_secret" },
        { TLV_LOGGER_SYSLOG, "logger_syslog" },
        { TLV_LOGGER_SYSLOG_LEVEL, "logger_syslog_level" },
        { TLV_MBO, "mbo" },
        { TLV_MBO_CELL_DATA_CONN_PREF, "mbo_cell_data_conn_pref" },
        { TLV_BSS_TRANSITION, "bss_transition" },
        { TLV_INTERWORKING, "interworking" },
        { TLV_RRM_NEIGHBOR_REPORT, "rrm_neighbor_report" },
        { TLV_RRM_BEACON_REPORT, "rrm_beacon_report" },
        { TLV_COUNTRY3, "country3" },
        { TLV_MBO_CELL_CAPA, "mbo_cell_capa" },
        { TLV_HE_OPER_CHWIDTH, "he_oper_chwidth" },
        { TLV_IEEE80211_AX, "ieee80211ax" },
    };

    int i, j;

    sprintf(buffer, "ctrl_interface=/var/run/hostapd\nctrl_interface_group=0\ninterface=%s\n", DEFAULT_INTERFACE_NAME);

    for (i = 0; i < wrapper->tlv_num; i++) {
        for (j = 0; j < sizeof(maps)/sizeof(struct hostapd_tlv_to_config_name); j++) {
            if (wrapper->tlv[i]->id == maps[j].tlv_id) {
                char value[256];
                memset(value, 0, sizeof(value));
                memcpy(value, wrapper->tlv[i]->value, wrapper->tlv[i]->len);
                sprintf(buffer, "%s%s=%s\n", buffer, maps[j].config_name, value);
                break;
            }
        }
    }

    return strlen(buffer);
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'DUT configured as AP : Configuration file created'} 
int configure_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[10240];
    struct tlv_hdr *tlv;
    char *message = "DUT configured as AP : Configuration file created";

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_INTERFACE_NAME);
    if (tlv) {
        memcpy(buffer, tlv->value, tlv->len);
    }

    len = generate_hostapd_config(buffer, sizeof(buffer), req);
    if (len) {
        write_file("/etc/hostapd/hostapd.conf", buffer, len);
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len > 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'AP is up : Hostapd service is active'} 
int start_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char *message = TLV_VALUE_HOSTAPD_START_OK;
    int len;

    len = system("hostapd -B -P /run/hostapd.pid -g /run/hostapd-global -ddK -f /tmp/hostapd.log /etc/hostapd/hostapd.conf");

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// Bytes to DUT : 01 50 06 00 ed ff ff 00 55 0c 31 39 32 2e 31 36 38 2e 31 30 2e 33
// ACK  :{<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP :{<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'Static Ip successfully assigned to wireless interface'} 
int assign_static_ip_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[64];
    struct tlv_hdr *tlv;
    char *message = TLV_VALUE_ASSIGN_STATIC_IP_OK;

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_STATIC_IP);
    if (tlv) {
        memcpy(buffer, tlv->value, tlv->len);
    } else {
        message = "Failed.";
        goto response;
    }
   
    char *parameter[] = {"ifconfig", DEFAULT_INTERFACE_NAME, "up", buffer, "netmask", "255.255.255.0", NULL };

    len = pipe_command(buffer, sizeof(buffer), "/sbin/ifconfig", parameter);
    if (len) {
        message = TLV_VALUE_ASSIGN_STATIC_IP_NOT_OK;
    }

    response:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// Bytes to DUT : 01 50 01 00 ee ff ff 
// ACK:  Bytes from DUT : 01 00 01 00 ee ff ff a0 01 01 30 a0 00 15 41 43 4b 3a 20 43 6f 6d 6d 61 6e 64 20 72 65 63 65 69 76 65 64 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: '9c:b6:d0:19:40:c7', <IndigoResponseTLV.DUT_MAC_ADDR: 40963>: '9c:b6:d0:19:40:c7'} 
int get_mac_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char buffer[64];

    get_mac_address(buffer, sizeof(buffer), DEFAULT_INTERFACE_NAME);

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(buffer), buffer);
    fill_wrapper_tlv_bytes(resp, TLV_DUT_MAC_ADDR, strlen(buffer), buffer);

    return 0;
}

#define LOOPBACK_TIMEOUT            30

int start_loopback_server(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct tlv_hdr *tlv;
    char tool_ip[256];
    char tool_port[256];
    char local_ip[256];
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_LOOPBACK_SVR_START_NOT_OK;

    /* ControlApp on DUT */
    /* TLV: TLV_TOOL_IP_ADDRESS */
    memset(tool_ip, 0, sizeof(tool_ip));
    tlv = find_wrapper_tlv_by_id(req, TLV_TOOL_IP_ADDRESS);
    if (tlv) {
        memcpy(tool_ip, tlv->value, tlv->len);
    } else {
        goto response;
    }
    /* TLV: TLV_TOOL_UDP_PORT */
    tlv = find_wrapper_tlv_by_id(req, TLV_TOOL_UDP_PORT);
    if (tlv) {
        memcpy(tool_port, tlv->value, tlv->len);
    } else {
        goto response;
    }
    /* Find network interface. If br0 exists, then use it. Otherwise, it uses the initiation value. */
    memset(local_ip, 0, sizeof(local_ip));
    if (find_interface_ip(local_ip, sizeof(local_ip), "br0")) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", "br0");
    } else if (find_interface_ip(local_ip, sizeof(local_ip), DEFAULT_INTERFACE_NAME)) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", DEFAULT_INTERFACE_NAME);
    } else if (find_interface_ip(local_ip, sizeof(local_ip), "eth0")) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", "eth0");
    } else {
        indigo_logger(LOG_LEVEL_DEBUG, "No availabe interface");
    }
    /* Start loopback */
    if (!loopback_client_start(tool_ip, atoi(tool_port), local_ip, atoi(tool_port), LOOPBACK_TIMEOUT)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_LOOPBACK_SVR_START_OK;
    }
response:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// ACK:  {"status": 0, "message": "ACK: Command received", "tlvs": {}} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'Loopback server in idle state'} 
int stop_loop_back_server_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    /* Stop loopback */
    if (loopback_client_status()) {
        loopback_client_stop();
    }
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_LOOP_BACK_STOP_OK), TLV_VALUE_LOOP_BACK_STOP_OK);

    return 0;
}
