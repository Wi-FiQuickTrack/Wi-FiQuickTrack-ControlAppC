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
#include "wpa_ctrl.h"
#include "indigo_api_callback.h"


void register_apis() {
    /* Basic */
    register_api(API_GET_IP_ADDR, NULL, get_ip_addr_handler);
    register_api(API_GET_MAC_ADDR, NULL, get_mac_addr_handler);
    register_api(API_GET_CONTROL_APP_VERSION, NULL, get_control_app_handler);
    register_api(API_INDIGO_START_LOOP_BACK_SERVER, NULL, start_loopback_server);
    register_api(API_INDIGO_STOP_LOOP_BACK_SERVER, NULL, stop_loop_back_server_handler);
    register_api(API_INDIGO_SEND_LOOP_BACK_DATA, NULL, send_loopback_data_handler);
    /* TODO: API_CREATE_NEW_INTERFACE_BRIDGE_NETWORK */
    register_api(API_ASSIGN_STATIC_IP, NULL, assign_static_ip_handler);
    register_api(API_DEVICE_RESET, NULL, reset_device_handler);
    /* AP */
    register_api(API_AP_START_UP, NULL, start_ap_handler);
    register_api(API_AP_STOP, NULL, stop_ap_handler);
    register_api(API_AP_CONFIGURE, NULL, configure_ap_handler);
    register_api(API_AP_TRIGGER_CHANSWITCH, NULL, trigger_ap_channel_switch);
    register_api(API_AP_SEND_DISCONNECT, NULL, send_ap_disconnect_handler);
    register_api(API_AP_SET_PARAM , NULL, set_ap_parameter_handler);
    register_api(API_AP_SEND_BTM_REQ, NULL, send_ap_btm_handler);
    /* STA */
    register_api(API_STA_ASSOCIATE, NULL, associate_sta_handler);
    register_api(API_STA_CONFIGURE, NULL, configure_sta_handler);
    register_api(API_STA_DISCONNECT, NULL, stop_sta_handler);
    register_api(API_STA_SEND_DISCONNECT, NULL, send_sta_disconnect_handler);
    register_api(API_STA_REASSOCIATE, NULL, send_sta_reconnect_handler);
    register_api(API_STA_SET_PARAM, NULL, set_sta_parameter_handler);
    register_api(API_STA_SEND_BTM_QUERY, NULL, send_sta_btm_query_handler);
    register_api(API_STA_SEND_ANQP_QUERY, NULL, send_sta_anqp_query_handler);
    register_api(API_STA_START_UP, NULL, start_up_sta_handler);
}

static int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_OK), TLV_VALUE_OK);
    fill_wrapper_tlv_bytes(resp, TLV_CONTROL_APP_VERSION, strlen(TLV_VALUE_APP_VERSION), TLV_VALUE_APP_VERSION);
    return 0;
}

#define DEBUG_LEVEL_DISABLE             0
#define DEBUG_LEVEL_BASIC               1
#define DEBUG_LEVEL_ADVANCED            2

int hostapd_debug_level = DEBUG_LEVEL_DISABLE;
int wpas_debug_level = DEBUG_LEVEL_DISABLE;

static int get_debug_level(int value) {
    if (value == 0) {
        return DEBUG_LEVEL_DISABLE;
    } else if (value == 1) {
        return DEBUG_LEVEL_BASIC;
    }
    return DEBUG_LEVEL_ADVANCED;
}

static void set_hostapd_debug_level(int level) {
    hostapd_debug_level = level;
}

static void set_wpas_debug_level(int level) {
    wpas_debug_level = level;
}

static char* get_hostapd_debug_arguments() {
    if (hostapd_debug_level == DEBUG_LEVEL_ADVANCED) {
        return "-dddK";
    } else if (hostapd_debug_level == DEBUG_LEVEL_BASIC) {
        return "-dK";
    }
    return "";
}

static char* get_wpas_debug_arguments() {
    if (wpas_debug_level == DEBUG_LEVEL_ADVANCED) {
        return "-ddd";
    } else if (wpas_debug_level == DEBUG_LEVEL_BASIC) {
        return "-d";
    }
    return "";
}

static int reset_device_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len, status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_RESET_NOT_OK;
    char buffer[TLV_VALUE_SIZE];
    char role[TLV_VALUE_SIZE], log_level[TLV_VALUE_SIZE], clear[TLV_VALUE_SIZE];
    struct tlv_hdr *tlv = NULL;

    /* TLV: ROLE */
    tlv = find_wrapper_tlv_by_id(req, TLV_ROLE);
    memset(role, 0, sizeof(role));
    if (tlv) {
        memcpy(role, tlv->value, tlv->len);
    } else {
        goto done;
    }
    /* TLV: DEBUG_LEVEL */
    tlv = find_wrapper_tlv_by_id(req, TLV_DEBUG_LEVEL);
    memset(log_level, 0, sizeof(log_level));
    if (tlv) {
        memcpy(log_level, tlv->value, tlv->len);
    }
    /* TLV: CLEAR */
    tlv = find_wrapper_tlv_by_id(req, TLV_CLEAR);
    memset(clear, 0, sizeof(clear));
    if (tlv) {
        memcpy(clear, tlv->value, tlv->len);
    }

    if (atoi(role) == DUT_TYPE_STAUT) {
        system("killall wpa_supplicant");
        sleep(1);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "ifconfig %s 0.0.0.0", get_wireless_interface());
        system(buffer);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "cp -rf sta_reset_config.conf %s", get_wpas_conf_file());
        system(buffer);
        if (strlen(log_level)) {
            set_wpas_debug_level(get_debug_level(atoi(log_level)));
        }
    } else if (atoi(role) == DUT_TYPE_APUT) {
        system("killall hostapd");
        sleep(1);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "ifconfig %s 0.0.0.0", get_wireless_interface());
        system(buffer);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "cp -rf ap_reset_config.conf %s", get_hapd_conf_file());
        system(buffer);
        if (strlen(log_level)) {
            set_hostapd_debug_level(get_debug_level(atoi(log_level)));
        }
    }
    sleep(1);

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_RESET_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'AP stop completed : Hostapd service is inactive.'} 
static int stop_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[S_BUFFER_LEN];
    char *parameter[] = {"pidof", "hostapd", NULL};
    char *message = NULL;

    memset(buffer, 0, sizeof(buffer));

    system("killall hostapd 1>/dev/null 2>/dev/null");
    sleep(2);

    sprintf(buffer, "rm -rf %s", get_hapd_conf_file());
    len = system(buffer);
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove hostapd.conf");
    }
    sleep(1);

#ifdef _OPENWRT_
#else
    len = system("rfkill unblock wlan");
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to run rfkill unblock wlan");
    }
    sleep(1);
#endif

    len = pipe_command(buffer, sizeof(buffer), "/bin/pidof", parameter);
    if (len) {
        message = TLV_VALUE_HOSTAPD_STOP_NOT_OK;
    } else {
        message = TLV_VALUE_HOSTAPD_STOP_OK;
    }

#ifdef _OPENWRT_
    sprintf(buffer, "iw dev %s del", get_wireless_interface());
    system(buffer);
#endif

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
   
    return 0;
}

static char* find_hostapd_config_name(int tlv_id) {
    int i;
    for (i = 0; i < sizeof(maps)/sizeof(struct tlv_to_config_name); i++) {
        if (tlv_id == maps[i].tlv_id) {
            return maps[i].config_name;
        }
    }
    return NULL;
}

static struct tlv_to_config_name* find_hostapd_config(int tlv_id) {
    int i;
    for (i = 0; i < sizeof(maps)/sizeof(struct tlv_to_config_name); i++) {
        if (tlv_id == maps[i].tlv_id) {
            return &maps[i];
        }
    }
    return NULL;
}

static int get_center_freq_index(int channel, int width) {
    if (width == 1) {
        if (channel >= 36 && channel <= 48) {
            return 42;
        } else if (channel <= 64) {
            return 58;
        } else if (channel >= 100 && channel <= 112) {
            return 106;
        } else if (channel <= 128) {
            return 122;
        } else if (channel <= 144) {
            return 138;
        } else if (channel >= 149 && channel <= 161) {
            return 155;
        }
    } else if (width == 2) {
        if (channel >= 36 && channel <= 64) {
            return 50;
        } else if (channel >= 36 && channel <= 64) {
            return 114;
        }
    }
    return 0;
}

#ifdef _RESERVED_
/* The function is reserved for the defeault hostapd config */
#define HOSTAPD_DEFAULT_CONFIG_SSID                 "Indigo"
#define HOSTAPD_DEFAULT_CONFIG_CHANNEL              "36"
#define HOSTAPD_DEFAULT_CONFIG_HW_MODE              "a"
#define HOSTAPD_DEFAULT_CONFIG_WPA_PASSPHRASE       "12345678"
#define HOSTAPD_DEFAULT_CONFIG_IEEE80211N           "1"
#define HOSTAPD_DEFAULT_CONFIG_WPA                  "2"
#define HOSTAPD_DEFAULT_CONFIG_WPA_KEY_MGMT         "WPA-PSK"
#define HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE         "CCMP"

static void append_hostapd_default_config(struct packet_wrapper *wrapper) {
    if (find_wrapper_tlv_by_id(wrapper, TLV_SSID) == NULL) {
        add_wrapper_tlv(wrapper, TLV_SSID, strlen(HOSTAPD_DEFAULT_CONFIG_SSID), HOSTAPD_DEFAULT_CONFIG_SSID);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_CHANNEL) == NULL) {
        add_wrapper_tlv(wrapper, TLV_CHANNEL, strlen(HOSTAPD_DEFAULT_CONFIG_CHANNEL), HOSTAPD_DEFAULT_CONFIG_CHANNEL);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_HW_MODE) == NULL) {
        add_wrapper_tlv(wrapper, TLV_HW_MODE, strlen(HOSTAPD_DEFAULT_CONFIG_HW_MODE), HOSTAPD_DEFAULT_CONFIG_HW_MODE);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_WPA_PASSPHRASE) == NULL) {
        add_wrapper_tlv(wrapper, TLV_WPA_PASSPHRASE, strlen(HOSTAPD_DEFAULT_CONFIG_WPA_PASSPHRASE), HOSTAPD_DEFAULT_CONFIG_WPA_PASSPHRASE);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_IEEE80211_N) == NULL) {
        add_wrapper_tlv(wrapper, TLV_IEEE80211_N, strlen(HOSTAPD_DEFAULT_CONFIG_IEEE80211N), HOSTAPD_DEFAULT_CONFIG_IEEE80211N);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_WPA) == NULL) {
        add_wrapper_tlv(wrapper, TLV_WPA, strlen(HOSTAPD_DEFAULT_CONFIG_WPA), HOSTAPD_DEFAULT_CONFIG_WPA);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_WPA_KEY_MGMT) == NULL) {
        add_wrapper_tlv(wrapper, TLV_WPA_KEY_MGMT, strlen(HOSTAPD_DEFAULT_CONFIG_WPA_KEY_MGMT), HOSTAPD_DEFAULT_CONFIG_WPA_KEY_MGMT);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_RSN_PAIRWISE) == NULL) {
        add_wrapper_tlv(wrapper, TLV_RSN_PAIRWISE, strlen(HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE), HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE);
    }
}
#endif /* _RESERVED_ */

static void add_mu_edca_params(char *output) {
    strcat(output, "he_mu_edca_ac_be_aifsn=0\n");
    strcat(output, "he_mu_edca_ac_be_ecwmin=15\n");
    strcat(output, "he_mu_edca_ac_be_ecwmax=15\n");
    strcat(output, "he_mu_edca_ac_be_timer=255\n");
    strcat(output, "he_mu_edca_ac_bk_aifsn=0\n");
    strcat(output, "he_mu_edca_ac_bk_aci=1\n");
    strcat(output, "he_mu_edca_ac_bk_ecwmin=15\n");
    strcat(output, "he_mu_edca_ac_bk_ecwmax=15\n");
    strcat(output, "he_mu_edca_ac_bk_timer=255\n");
    strcat(output, "he_mu_edca_ac_vi_aifsn=0\n");
    strcat(output, "he_mu_edca_ac_vi_aci=2\n");
    strcat(output, "he_mu_edca_ac_vi_ecwmin=15\n");
    strcat(output, "he_mu_edca_ac_vi_ecwmax=15\n");
    strcat(output, "he_mu_edca_ac_vi_timer=255\n");
    strcat(output, "he_mu_edca_ac_vo_aifsn=0\n");
    strcat(output, "he_mu_edca_ac_vo_aci=3\n");
    strcat(output, "he_mu_edca_ac_vo_ecwmin=15\n");
    strcat(output, "he_mu_edca_ac_vo_ecwmax=15\n");
    strcat(output, "he_mu_edca_ac_vo_timer=255\n");
}

static int generate_hostapd_config(char *output, int output_size, struct packet_wrapper *wrapper, char *ifname) {
    int i, ctrl_iface = 0;
    char buffer[S_BUFFER_LEN], cfg_item[2*S_BUFFER_LEN];

    struct tlv_to_config_name* cfg = NULL;
    struct tlv_hdr *tlv = NULL;

    sprintf(output, "ctrl_interface_group=0\ninterface=%s\n", ifname);

#ifdef _RESERVED_
    /* The function is reserved for the defeault hostapd config */
    append_hostapd_default_config(wrapper);
#endif

    for (i = 0; i < wrapper->tlv_num; i++) {
        tlv = wrapper->tlv[i];
        cfg = find_hostapd_config(tlv->id);
        if (!cfg) {
            indigo_logger(LOG_LEVEL_ERROR, "Unknown AP configuration name: TLV ID 0x%04x", tlv->id);
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, tlv->value, tlv->len);
        sprintf(cfg_item, "%s=%s\n", cfg->config_name, buffer);
        strcat(output, cfg_item);

        if (tlv->id == TLV_CONTROL_INTERFACE) {
            ctrl_iface = 1;
            set_hapd_ctrl_path(tlv->value);
        }
        if (tlv->id == TLV_HE_MU_EDCA)
            add_mu_edca_params(output);
    }
    if (ctrl_iface == 0) {
        indigo_logger(LOG_LEVEL_ERROR, "No Remote UDP ctrl interface TLV for TP");
        return 0;
    }

    return strlen(output);
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'DUT configured as AP : Configuration file created'} 
static int configure_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[L_BUFFER_LEN], ifname[S_BUFFER_LEN];
    struct tlv_hdr *tlv;
    char *message = "DUT configured as AP : Configuration file created";

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_INTERFACE_NAME);
    memset(ifname, 0, sizeof(ifname));
    if (tlv) {
        memcpy(ifname, tlv->value, tlv->len);
    } else {
        sprintf(ifname, "%s", get_wireless_interface());
    }

    len = generate_hostapd_config(buffer, sizeof(buffer), req, ifname);
    if (len) {
        write_file(get_hapd_conf_file(), buffer, len);
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len > 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'AP is up : Hostapd service is active'} 
static int start_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char *message = TLV_VALUE_HOSTAPD_START_OK;
    char buffer[S_BUFFER_LEN], g_ctrl_iface[64];
    int len;
    struct tlv_hdr *tlv;

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_GLOBAL_CTRL_IFACE);
    memset(g_ctrl_iface, 0, sizeof(g_ctrl_iface));
    if (tlv) {
        memcpy(g_ctrl_iface, tlv->value, tlv->len);
    } else {
        sprintf(g_ctrl_iface, "%s", get_hapd_global_ctrl_path());
    }
#ifdef _OPENWRT_
    sprintf(buffer, "iw phy phy1 interface add %s type managed", get_wireless_interface());
    system(buffer);
    sleep(1);

    sprintf(buffer, "hostapd -B -P /var/run/hostapd.pid -g %s %s -f /var/log/hostapd.log %s",
        g_ctrl_iface, get_hostapd_debug_arguments(), get_hapd_conf_file());
#else
    sprintf(buffer, "hostapd -B -P /var/run/hostapd.pid -g %s %s %s -f /var/log/hostapd.log",
        g_ctrl_iface, get_hostapd_debug_arguments(), get_hapd_conf_file());
#endif
    len = system(buffer);
    sleep(1);

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// Bytes to DUT : 01 50 06 00 ed ff ff 00 55 0c 31 39 32 2e 31 36 38 2e 31 30 2e 33
// ACK  :{<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP :{<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'Static Ip successfully assigned to wireless interface'} 
static int assign_static_ip_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
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
   
    char *parameter[] = {"ifconfig", get_wireless_interface(), "up", buffer, "netmask", "255.255.255.0", NULL };

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
static int get_mac_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char buffer[64];

    get_mac_address(buffer, sizeof(buffer), get_wireless_interface());

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(buffer), buffer);
    fill_wrapper_tlv_bytes(resp, TLV_DUT_MAC_ADDR, strlen(buffer), buffer);

    return 0;
}

static int start_loopback_server(struct packet_wrapper *req, struct packet_wrapper *resp) {
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
        goto done;
    }
    /* TLV: TLV_TOOL_UDP_PORT */
    tlv = find_wrapper_tlv_by_id(req, TLV_TOOL_UDP_PORT);
    if (tlv) {
        memcpy(tool_port, tlv->value, tlv->len);
    } else {
        goto done;
    }
    /* Find network interface. If br0 exists, then use it. Otherwise, it uses the initiation value. */
    memset(local_ip, 0, sizeof(local_ip));
    if (find_interface_ip(local_ip, sizeof(local_ip), "br0")) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", "br0");
    } else if (find_interface_ip(local_ip, sizeof(local_ip), get_wireless_interface())) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", get_wireless_interface());
// #ifdef __TEST__        
    } else if (find_interface_ip(local_ip, sizeof(local_ip), "eth0")) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", "eth0");
// #endif /* __TEST__ */
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "No availabe interface");
        goto done;
    }
    /* Start loopback */
    if (!loopback_client_start(tool_ip, atoi(tool_port), local_ip, atoi(tool_port), LOOPBACK_TIMEOUT)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_LOOPBACK_SVR_START_OK;
    }
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// ACK:  {"status": 0, "message": "ACK: Command received", "tlvs": {}} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'Loopback server in idle state'} 
static int stop_loop_back_server_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    /* Stop loopback */
    if (loopback_client_status()) {
        loopback_client_stop();
    }
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_LOOP_BACK_STOP_OK), TLV_VALUE_LOOP_BACK_STOP_OK);

    return 0;
}


static int send_loopback_data_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct tlv_hdr *tlv;
    char dut_ip[64];
    char dut_port[32];
    char rate[16], pkt_count[16], pkt_size[16];
    int status = TLV_VALUE_STATUS_NOT_OK, recvd = 0;
    char *message = TLV_VALUE_SEND_LOOPBACK_DATA_NOT_OK;

    /* TLV: TLV_DUT_IP_ADDRESS */
    memset(dut_ip, 0, sizeof(dut_ip));
    tlv = find_wrapper_tlv_by_id(req, TLV_DUT_IP_ADDRESS);
    if (tlv) {
        memcpy(dut_ip, tlv->value, tlv->len);
    } else {
        goto done;
    }
    /* TODO:   TLV: TLV_DUT_UDP_PORT ? */
    tlv = find_wrapper_tlv_by_id(req, TLV_TOOL_UDP_PORT);
    if (tlv) {
        memcpy(dut_port, tlv->value, tlv->len);
    } else {
        goto done;
    }

    tlv = find_wrapper_tlv_by_id(req, TLV_UDP_PACKET_RATE);
    if (tlv) {
        memcpy(rate, tlv->value, tlv->len);
    } else {
        snprintf(rate, sizeof(rate), "1");
    }

    tlv = find_wrapper_tlv_by_id(req, TLV_PACKET_COUNT);
    if (tlv) {
        memcpy(pkt_count, tlv->value, tlv->len);
    } else {
        snprintf(pkt_count, sizeof(pkt_count), "10");
    }

    tlv = find_wrapper_tlv_by_id(req, TLV_UDP_PACKET_SIZE);
    if (tlv) {
        memcpy(pkt_size, tlv->value, tlv->len);
    } else {
        snprintf(pkt_size, sizeof(pkt_size), "1000");
    }

    /* Start loopback */
    recvd = send_loopback_data(dut_ip, atoi(dut_port), atoi(pkt_count), atoi(pkt_size), atoi(rate));
    if (recvd > 0) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_SEND_LOOPBACK_DATA_OK;
    }
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    fill_wrapper_tlv_byte(resp, TLV_LOOP_BACK_DATA_RECEIVED, recvd);

    return 0;
}

static int send_ap_disconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len, status = TLV_VALUE_STATUS_NOT_OK;
    char buffer[S_BUFFER_LEN];
    char response[S_BUFFER_LEN];
    char address[32];
    char *parameter[] = {"pidof", "hostapd", NULL};
    char *message = NULL;
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    size_t resp_len;

    /* Check hostapd status. TODO: it may use UDS directly */
    memset(buffer, 0, sizeof(buffer));
    len = pipe_command(buffer, sizeof(buffer), "/bin/pidof", parameter);
    if (len == 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to find hostapd PID");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_HOSTAPD_NOT_OK;
        goto done;
    }
    /* Open hostapd UDS socket */
    w = wpa_ctrl_open(get_hapd_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to hostapd");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_HOSTAPD_CTRL_NOT_OK;
        goto done;
    }
    /* ControlApp on DUT */
    /* TLV: TLV_ADDRESS */
    memset(address, 0, sizeof(address));
    tlv = find_wrapper_tlv_by_id(req, TLV_ADDRESS);
    if (tlv) {
        memcpy(address, tlv->value, tlv->len);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV:Address");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        goto done;
    }
    /* Assemble hostapd command */
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "DISASSOCIATE %s reason=1", address);
    /* Send command to hostapd UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        message = TLV_VALUE_HOSTAPD_RESP_NOT_OK;
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_HOSTAPD_STOP_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int set_ap_parameter_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = NULL;
    char buffer[8192];
    char response[1024];
    char param_name[32];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open hostapd UDS socket */
    w = wpa_ctrl_open(get_hapd_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to hostapd");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_HOSTAPD_CTRL_NOT_OK;
        goto done;
    }

    /* ControlApp on DUT */
    /* TLV: MBO_ASSOC_DISALLOW or GAS_COMEBACK_DELAY */
    memset(param_value, 0, sizeof(param_value));
    tlv = find_wrapper_tlv_by_id(req, TLV_MBO_ASSOC_DISALLOW);
    if (!tlv) {
        find_wrapper_tlv_by_id(req, TLV_GAS_COMEBACK_DELAY);
    }
    if (tlv && find_hostapd_config_name(tlv->id) != NULL) {
        strcpy(param_name, find_hostapd_config_name(tlv->id));
        memcpy(param_value, tlv->value, tlv->len);
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_MBO_ASSOC_DISALLOW or TLV_GAS_COMEBACK_DELAY");
        goto done;
    }
    /* Assemble hostapd command */
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "SET %s %s", param_name, param_value);
    /* Send command to hostapd UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        message = TLV_VALUE_HOSTAPD_RESP_NOT_OK;
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_ap_btm_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = NULL;
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    char request[4096];
    char response[4096];
    char buffer[512];

    char bssid[256];
    char disassoc_imminent[256];
    char disassoc_timer[256];
    char reassoc_retry_delay[256];
    char bss_term_bit[256];
    char bss_term_tsf[256];
    char bss_term_duration[256];

    memset(bssid, 0, sizeof(bssid));
    memset(disassoc_imminent, 0, sizeof(disassoc_imminent));
    memset(disassoc_timer, 0, sizeof(disassoc_timer));
    memset(reassoc_retry_delay, 0, sizeof(reassoc_retry_delay));
    memset(bss_term_bit, 0, sizeof(bss_term_bit));
    memset(bss_term_tsf, 0, sizeof(bss_term_tsf));
    memset(bss_term_duration, 0, sizeof(bss_term_duration));

    /* ControlApp on DUT */
    /* TLV: BSSID (required) */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSSID);
    if (tlv) {
        memcpy(bssid, tlv->value, tlv->len);
    }
    /* DISASSOC_IMMINENT            disassoc_imminent=%s */
    tlv = find_wrapper_tlv_by_id(req, TLV_DISASSOC_IMMINENT);
    if (tlv) {
        memcpy(disassoc_imminent, tlv->value, tlv->len);
    }
    /* DISASSOC_TIMER               disassoc_timer=%s */
    tlv = find_wrapper_tlv_by_id(req, TLV_DISASSOC_TIMER);
    if (tlv) {
        memcpy(disassoc_timer, tlv->value, tlv->len);
    }
    /* REASSOCIAITION_RETRY_DELAY   mbo=0:{}:0 */
    tlv = find_wrapper_tlv_by_id(req, TLV_REASSOCIAITION_RETRY_DELAY);
    if (tlv) {
        memcpy(reassoc_retry_delay, tlv->value, tlv->len);
    }
    /* TODO: CANDIDATE_LIST */
    /* BSS_TERMINATION              bss_term_bit */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSS_TERMINATION);
    if (tlv) {
        memcpy(bss_term_bit, tlv->value, tlv->len);
    }
    /* BSS_TERMINATION_TSF          bss_term_tsf */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSS_TERMINATION_TSF);
    if (tlv) {
        memcpy(bss_term_tsf, tlv->value, tlv->len);
    }
    /* BSS_TERMINATION_DURATION     bss_term_duration */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSS_TERMINATION_DURATION);
    if (tlv) {
        memcpy(bss_term_duration, tlv->value, tlv->len);
    }

    /* Assemble hostapd command for BSS_TM_REQ */
    memset(request, 0, sizeof(request));
    sprintf(request, "BSS_TM_REQ %s", bssid);
    /*  disassoc_imminent=%s */
    if (strlen(disassoc_imminent)) {
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, " disassoc_imminent=%s", disassoc_imminent);
        strcat(request, buffer);
    }
    /* disassoc_timer=%s */
    if (strlen(disassoc_timer)) {
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, " disassoc_timer=%s", disassoc_timer);
        strcat(request, buffer);
    }
    /* reassoc_retry_delay=%s */
    if (strlen(reassoc_retry_delay)) {
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, " mbo=0:%s:0", reassoc_retry_delay);
        strcat(request, buffer);
    }
    /* if bss_term_bit && bss_term_tsf && bss_term_duration, then bss_term={bss_term_tsf},{bss_term_duration} */
    if (strlen(bss_term_bit) && strlen(bss_term_tsf) && strlen(bss_term_duration) ) {
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, " mbo=0:%s:0", reassoc_retry_delay);
        strcat(request, buffer);
    }

    /* Open hostapd UDS socket */
    w = wpa_ctrl_open(get_hapd_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to hostapd");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_HOSTAPD_CTRL_NOT_OK;
        goto done;
    }
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, request, strlen(request), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        message = TLV_VALUE_HOSTAPD_RESP_NOT_OK;
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int trigger_ap_channel_switch(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = NULL;
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    char request[S_BUFFER_LEN];
    char response[S_BUFFER_LEN];

    char channel[64];
    char frequency[64];

    memset(channel, 0, sizeof(channel));
    memset(frequency, 0, sizeof(frequency));

    /* ControlApp on DUT */
    /* TLV: TLV_CHANNEL (required) */
    tlv = find_wrapper_tlv_by_id(req, TLV_CHANNEL);
    if (tlv) {
        memcpy(channel, tlv->value, tlv->len);
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_CHANNEL");
        goto done;
    }
    /* TLV_FREQUENCY (required) */
    tlv = find_wrapper_tlv_by_id(req, TLV_FREQUENCY);
    if (tlv) {
        memcpy(frequency, tlv->value, tlv->len);
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_FREQUENCY");
    }

    /* Assemble hostapd command for BSS_TM_REQ */
    memset(request, 0, sizeof(request));
    sprintf(request, "CHAN_SWITCH %s %s", channel, frequency);

    /* Open hostapd UDS socket */
    w = wpa_ctrl_open(get_hapd_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to hostapd");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_HOSTAPD_CTRL_NOT_OK;
        goto done;
    }
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, request, strlen(request), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        message = TLV_VALUE_HOSTAPD_RESP_NOT_OK;
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int get_ip_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = NULL;
    char buffer[64];

    if (find_interface_ip(buffer, sizeof(buffer), "br0")) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_OK;
    } else if (find_interface_ip(buffer, sizeof(buffer), get_wireless_interface())) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_OK;
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_NOT_OK;
    }

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (status == TLV_VALUE_STATUS_OK) {
        fill_wrapper_tlv_bytes(resp, TLV_DUT_WLAN_IP_ADDR, strlen(buffer), buffer);
    }
    return 0;
}

static int stop_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[S_BUFFER_LEN];
    char *parameter[] = {"pidof", "wpa_supplicant", NULL};
    char *message = NULL;

    system("killall wpa_supplicant 1>/dev/null 2>/dev/null");
    sleep(2);

    sprintf(buffer, "rm -rf %s", get_wpas_conf_file());
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove wpa_supplicant.conf");
    }
    sleep(1);

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "ifconfig %s 0.0.0.0", get_wireless_interface());
    len = system(buffer);
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to free IP address");
    }
    sleep(1);

    len = pipe_command(buffer, sizeof(buffer), "/bin/pidof", parameter);
    if (len) {
        message = TLV_VALUE_WPA_S_STOP_NOT_OK;
    } else {
        message = TLV_VALUE_WPA_S_STOP_OK;
    }

#ifdef _OPENWRT_
    sprintf(buffer, "iw dev %s del", get_wireless_interface());
    system(buffer);
#endif

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len == 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
   
    return 0;
}

struct tlv_to_config_name* find_wpas_global_config_name(int tlv_id) {
    int i;
    for (i = 0; i < sizeof(wpas_global_maps)/sizeof(struct tlv_to_config_name); i++) {
        if (tlv_id == wpas_global_maps[i].tlv_id) {
            return &wpas_global_maps[i];
        }
    }
    return NULL;
}

#ifdef _RESERVED_
/* The function is reserved for the defeault wpas config */
#define WPAS_DEFAULT_CONFIG_SSID                    "Indigo"
#define WPAS_DEFAULT_CONFIG_WPA_KEY_MGMT            "WPA-PSK"
#define WPAS_DEFAULT_CONFIG_PROTO                   "RSN"
#define HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE         "CCMP"
#define WPAS_DEFAULT_CONFIG_WPA_PASSPHRASE          "12345678"

static void append_wpas_network_default_config(struct packet_wrapper *wrapper) {
    if (find_wrapper_tlv_by_id(wrapper, TLV_SSID) == NULL) {
        add_wrapper_tlv(wrapper, TLV_SSID, strlen(WPAS_DEFAULT_CONFIG_SSID), WPAS_DEFAULT_CONFIG_SSID);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_WPA_KEY_MGMT) == NULL) {
        add_wrapper_tlv(wrapper, TLV_WPA_KEY_MGMT, strlen(WPAS_DEFAULT_CONFIG_WPA_KEY_MGMT), WPAS_DEFAULT_CONFIG_WPA_KEY_MGMT);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_PROTO) == NULL) {
        add_wrapper_tlv(wrapper, TLV_PROTO, strlen(WPAS_DEFAULT_CONFIG_PROTO), WPAS_DEFAULT_CONFIG_PROTO);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_RSN_PAIRWISE) == NULL) {
        add_wrapper_tlv(wrapper, TLV_RSN_PAIRWISE, strlen(HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE), HOSTAPD_DEFAULT_CONFIG_RSN_PAIRWISE);
    }
    if (find_wrapper_tlv_by_id(wrapper, TLV_WPA_PASSPHRASE) == NULL) {
        add_wrapper_tlv(wrapper, TLV_WPA_PASSPHRASE, strlen(WPAS_DEFAULT_CONFIG_WPA_PASSPHRASE), WPAS_DEFAULT_CONFIG_WPA_PASSPHRASE);
    }
}
#endif /* _RESERVED_ */

static int generate_wpas_config(char *buffer, int buffer_size, struct packet_wrapper *wrapper) {
    int i, j;
    char value[S_BUFFER_LEN], cfg_item[2*S_BUFFER_LEN];
    int ieee80211w_configured = 0;
    int transition_mode_enabled = 0;
    int owe_configured = 0;
    char port[16];
    struct tlv_hdr *tlv = NULL;

    struct tlv_to_config_name* cfg = NULL;

    tlv = find_wrapper_tlv_by_id(wrapper, TLV_CONTROL_INTERFACE);
    if (tlv) {
        set_wpas_ctrl_path(tlv->value);
    } else {
        return 0;
    }

    sprintf(buffer, "ap_scan=1\npmf=1\n");

    for (i = 0; i < wrapper->tlv_num; i++) {
        cfg = find_wpas_global_config_name(wrapper->tlv[i]->id);
        if (cfg) {
            memset(value, 0, sizeof(value));
            memcpy(value, wrapper->tlv[i]->value, wrapper->tlv[i]->len);
            sprintf(cfg_item, "%s=%s\n", cfg->config_name, value);
            strcat(buffer, cfg_item);
        }
    }
    strcat(buffer, "network={\n");

#ifdef _RESERVED_
    /* The function is reserved for the defeault wpas config */
    append_wpas_network_default_config(wrapper);
#endif /* _RESERVED_ */

    for (i = 0; i < wrapper->tlv_num; i++) {
        cfg = find_hostapd_config(wrapper->tlv[i]->id);
        if (cfg && find_wpas_global_config_name(wrapper->tlv[i]->id) == NULL) {
            memset(value, 0, sizeof(value));
            memcpy(value, wrapper->tlv[i]->value, wrapper->tlv[i]->len);

            if (wrapper->tlv[i]->id == TLV_KEY_MGMT) {
                if (strstr(value, "WPA-PSK") || strstr(value, "SAE")) {
                    transition_mode_enabled = 1;
                }
                if (strstr(value, "OWE")) {
                    owe_configured = 1;
                }
            }

            if (cfg->quoted) {
                sprintf(cfg_item, "%s=\"%s\"\n", cfg->config_name, value);
                strcat(buffer, cfg_item);
            } else {
                sprintf(cfg_item, "%s=%s\n", cfg->config_name, value);
                strcat(buffer, cfg_item);
            }
        }        
    }

    if (ieee80211w_configured == 0 && transition_mode_enabled) {
        strcat(buffer, "ieee80211w=1\n");
    } else if (owe_configured) {
        strcat(buffer, "ieee80211w=2\n");
    }

    /* TODO: merge another file */
    /* python source code:
        if merge_config_file:
        appended_supplicant_conf_str = ""
        existing_conf = StaCommandHelper.get_existing_supplicant_conf()
        wpa_supplicant_dict = StaCommandHelper.__convert_config_str_to_dict(config = wps_config)
        for each_key in existing_conf:
            if each_key not in wpa_supplicant_dict:
                wpa_supplicant_dict[each_key] = existing_conf[each_key]

        for each_supplicant_conf in wpa_supplicant_dict:
            appended_supplicant_conf_str += each_supplicant_conf + "=" + wpa_supplicant_dict[each_supplicant_conf] + "\n"
        wps_config = appended_supplicant_conf_str.rstrip()
    */

    strcat(buffer, "}\n");

    return strlen(buffer);
}

static int configure_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len;
    char buffer[L_BUFFER_LEN];
    struct tlv_hdr *tlv;
    char *message = "Test Platform configured as STA : Configuration file created";

    memset(buffer, 0, sizeof(buffer));
    len = generate_wpas_config(buffer, sizeof(buffer), req);
    if (len) {
        write_file(get_wpas_conf_file(), buffer, len);
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len > 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int associate_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_ASSOC_OK;
    char buffer[256], response[1024];
    int len, status = TLV_VALUE_STATUS_NOT_OK, i;
    size_t resp_len;

#ifdef _OPENWRT_
#else
    system("rfkill unblock wlan");
    sleep(1);
#endif

    system("killall wpa_supplicant");
    sleep(3);

    /* Start WPA supplicant */
    memset(buffer, 0 ,sizeof(buffer));
#ifdef _OPENWRT_
    sprintf(buffer, "iw phy phy1 interface add %s type station", get_wireless_interface());
    system(buffer);
    sleep(1);

    sprintf(buffer, "wpa_supplicant -B -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
#else
    sprintf(buffer, "wpa_supplicant -B -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
#endif
    indigo_logger(LOG_LEVEL_DEBUG, "%s", buffer);
    len = system(buffer);
    sleep(5);

    /* Open WPA supplicant UDP socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_ASSOC_NOT_OK;
        goto done;
    }

    /* Send command to hostapd UDS socket */
    status = TLV_VALUE_STATUS_NOT_OK;
    message = TLV_VALUE_WPA_S_ASSOC_NOT_OK;
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "STATUS");    
    for (i = 0; i < 6; i++) {
        memset(response, 0, sizeof(response));
        resp_len = sizeof(response) - 1;
        wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
        printf("wpa ctrl response: %s\n", response);
        // Check link
        if (strstr(response, "wpa_state=COMPLETED")) {
            indigo_logger(LOG_LEVEL_DEBUG, "Connected");
            status = TLV_VALUE_STATUS_OK;
            message = TLV_VALUE_WPA_S_ASSOC_OK;            
            break;
        }
        sleep(2);
    }

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_disconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_DISCONNECT_NOT_OK;
    char buffer[256], response[1024];
    int status, i;
    size_t resp_len;

    /* Open WPA supplicant UDS socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_DISCONNECT_NOT_OK;
        goto done;
    }
    /* Send command to hostapd UDS socket */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "DISCONNECT");
    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_WPA_S_DISCONNECT_OK;
    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_reconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_RECONNECT_NOT_OK;
    char buffer[256], response[1024];
    int len, status, i;
    size_t resp_len;

    /* Open WPA supplicant UDS socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_RECONNECT_NOT_OK;
        goto done;
    }
    /* Send command to hostapd UDS socket */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "RECONNECT");
    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_WPA_S_RECONNECT_OK;
    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int set_sta_parameter_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = NULL;
    char buffer[BUFFER_LEN];
    char response[BUFFER_LEN];
    char param_name[32];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    /* ControlApp on DUT */
    /* TLV: MBO_IGNORE_ASSOC_DISALLOW */
    memset(param_value, 0, sizeof(param_value));
    tlv = find_wrapper_tlv_by_id(req, TLV_MBO_IGNORE_ASSOC_DISALLOW);
    if (tlv && find_hostapd_config_name(tlv->id) != NULL) {
        strcpy(param_name, find_hostapd_config_name(tlv->id));
        memcpy(param_value, tlv->value, tlv->len);
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: MBO_IGNORE_ASSOC_DISALLOW");
        goto done;
    }
    /* Assemble wpa_supplicant command */
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "SET %s %s", param_name, param_value);
    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_btm_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = TLV_VALUE_WPA_S_BTM_QUERY_NOT_OK;
    char buffer[1024];
    char response[1024];
    char reason_code[256];
    char candidate_list[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    /* TLV: BTMQUERY_REASON_CODE */
    tlv = find_wrapper_tlv_by_id(req, TLV_BTMQUERY_REASON_CODE);
    if (tlv) {
        memcpy(reason_code, tlv->value, tlv->len);
    } else {
        goto done;
    }

    /* TLV: TLV_CANDIDATE_LIST */
    tlv = find_wrapper_tlv_by_id(req, TLV_CANDIDATE_LIST);
    if (tlv) {
        memcpy(candidate_list, tlv->value, tlv->len);
    }

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "WNM_BSS_QUERY %s", reason_code);
    if (strcmp(candidate_list, "1") == 0) {
        strcat(buffer, " list");
    }

    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_anqp_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int len, status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_WPA_S_BTM_QUERY_NOT_OK;
    char buffer[1024];
    char response[1024];
    char bssid[256];
    char anqp_info_id[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    size_t resp_len;

    /* It may need to check whether to just scan */
    memset(buffer, 0, sizeof(buffer));
    len = sprintf(buffer, "ctrl_interface=%s\nap_scan=1\nnetwork={\nssid=\"Scanning\"\n}", WPAS_CTRL_PATH_DEFAULT);
    if (len) {
        write_file(get_wpas_conf_file(), buffer, len);
    }

    memset(buffer, 0 ,sizeof(buffer));
    sprintf(buffer, "wpa_supplicant -B -c %s -i %s", get_wpas_conf_file(), get_wireless_interface());
    len = system(buffer);
    sleep(2);

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(get_wpas_ctrl_path());
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    // SCAN
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "SCAN");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    sleep(5);

    /* TLV: BSSID */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSSID);
    if (tlv) {
        memcpy(bssid, tlv->value, tlv->len);
    } else {
        goto done;
    }

    /* TLV: ANQP_INFO_ID */
    tlv = find_wrapper_tlv_by_id(req, TLV_ANQP_INFO_ID);
    if (tlv) {
        memcpy(anqp_info_id, tlv->value, tlv->len);
    }

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "ANQP_GET %s", bssid);
    if (strcmp(anqp_info_id, "NeighborReportReq") == 0) {
        strcat(buffer, " 272");
    } else if (strcmp(anqp_info_id, "QueryListWithCellPref") == 0) {
        strcat(buffer, " mbo:2");
    }

    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    
    printf("%s -> resp: %s\n", buffer, response);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
    
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int start_up_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_START_UP_NOT_OK;
    char buffer[256], response[1024];
    int len, status = TLV_VALUE_STATUS_NOT_OK, i;
    size_t resp_len;
    char *parameter[] = {"pidof", "wpa_supplicant", NULL};
    struct tlv_hdr *tlv = NULL;

#ifdef _OPENWRT_
#else
    system("rfkill unblock wlan");
    sleep(1);
#endif

    system("killall wpa_supplicant");
    sleep(3);

    tlv = find_wrapper_tlv_by_id(req, TLV_CONTROL_INTERFACE);
    if (tlv) {
        set_wpas_ctrl_path(tlv->value);
        memset(buffer, 0, sizeof(buffer));
        len = sprintf(buffer, "ctrl_interface=%s\nap_scan=1\n", tlv->value);
        if (len) {
            write_file(get_wpas_conf_file(), buffer, len);
        }
    } else {
        return 0;
    }

    /* Start WPA supplicant */
    memset(buffer, 0 ,sizeof(buffer));
#ifdef _OPENWRT_
    sprintf(buffer, "iw phy phy1 interface add %s type station", get_wireless_interface());
    system(buffer);
    sleep(1);

    sprintf(buffer, "wpa_supplicant -B -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
#else
    sprintf(buffer, "wpa_supplicant -B -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
#endif
    len = system(buffer);
    sleep(2);

    len = pipe_command(buffer, sizeof(buffer), "/bin/pidof", parameter);
    if (len) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_WPA_S_START_UP_OK;
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_START_UP_NOT_OK;
    }

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}
