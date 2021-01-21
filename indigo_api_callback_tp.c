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
#include "vendor_specific.h"
#include "utils.h"
#include "wpa_ctrl.h"
#include "indigo_api_callback.h"

struct sta_platform_config sta_hw_config = {PHYMODE_AUTO, CHWIDTH_AUTO, false, false};

#ifdef _WTS_OPENWRT_
int rrm = 0, he_mu_edca = 0;
#endif

void register_apis() {
    /* Basic */
    register_api(API_GET_IP_ADDR, NULL, get_ip_addr_handler);
    register_api(API_GET_MAC_ADDR, NULL, get_mac_addr_handler);
    register_api(API_GET_CONTROL_APP_VERSION, NULL, get_control_app_handler);
    register_api(API_INDIGO_START_LOOP_BACK_SERVER, NULL, start_loopback_server);
    register_api(API_INDIGO_STOP_LOOP_BACK_SERVER, NULL, stop_loop_back_server_handler);
    register_api(API_INDIGO_SEND_LOOP_BACK_DATA, NULL, send_loopback_data_handler);
    register_api(API_INDIGO_STOP_LOOP_BACK_DATA, NULL, stop_loopback_data_handler);
    /* TODO: API_CREATE_NEW_INTERFACE_BRIDGE_NETWORK */
    register_api(API_ASSIGN_STATIC_IP, NULL, assign_static_ip_handler);
    register_api(API_DEVICE_RESET, NULL, reset_device_handler);
    /* AP */
    register_api(API_AP_START_UP, NULL, start_ap_handler);
    register_api(API_AP_STOP, NULL, stop_ap_handler);
    register_api(API_AP_CONFIGURE, NULL, configure_ap_handler);
    register_api(API_AP_SEND_ARP_MSGS, NULL, send_ap_arp_handler);
    /* STA */
    register_api(API_STA_ASSOCIATE, NULL, associate_sta_handler);
    register_api(API_STA_CONFIGURE, NULL, configure_sta_handler);
    register_api(API_STA_DISCONNECT, NULL, stop_sta_handler);
    register_api(API_STA_START_UP, NULL, start_up_sta_handler);
    register_api(API_STA_SET_PHY_MODE, NULL, set_sta_phy_mode_handler);
    register_api(API_STA_SET_CHANNEL_WIDTH, NULL, set_sta_channel_width_handler);
    register_api(API_STA_POWER_SAVE, NULL, set_sta_power_save_handler);
}

static int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_OK), TLV_VALUE_OK);
    fill_wrapper_tlv_bytes(resp, TLV_TEST_PLATFORM_APP_VERSION, 
        strlen(TLV_VALUE_TEST_PLATFORM_APP_VERSION), TLV_VALUE_TEST_PLATFORM_APP_VERSION);
    return 0;
}

#define DEBUG_LEVEL_DISABLE             0
#define DEBUG_LEVEL_BASIC               1
#define DEBUG_LEVEL_ADVANCED            2

int hostapd_debug_level = DEBUG_LEVEL_DISABLE;
int wpas_debug_level = DEBUG_LEVEL_BASIC;

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
        /* stop the wpa_supplicant and release IP address */
        system("killall wpa_supplicant >/dev/null 2>/dev/null");
        sleep(1);
        reset_interface_ip(get_wireless_interface());
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "cp -rf sta_reset_config.conf %s", get_wpas_conf_file());
        system(buffer);
        if (strlen(log_level)) {
            set_wpas_debug_level(get_debug_level(atoi(log_level)));
        }
    } else if (atoi(role) == DUT_TYPE_APUT) {
        /* stop the hostapd and release IP address */
        system("killall hostapd >/dev/null 2>/dev/null");
        sleep(1);
        reset_interface_ip(get_wireless_interface());
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
    int len = 0, reset = 0;
    char buffer[S_BUFFER_LEN], reset_type[16];
    char *parameter[] = {"pidof", "hostapd", NULL};
    char *message = NULL;
    struct tlv_hdr *tlv = NULL;

    /* TLV: RESET_TYPE */
    tlv = find_wrapper_tlv_by_id(req, TLV_RESET_TYPE);
    memset(reset_type, 0, sizeof(reset_type));
    if (tlv) {
        memcpy(reset_type, tlv->value, tlv->len);
        reset = atoi(reset_type);
        indigo_logger(LOG_LEVEL_DEBUG, "Reset Type: %d", reset);
    }
    memset(buffer, 0, sizeof(buffer));
#ifdef _OPENWRT_
    system("killall hostapd-wfa 1>/dev/null 2>/dev/null");
#else
    system("killall hostapd 1>/dev/null 2>/dev/null");
#endif
    sleep(2);

    len = unlink(get_hapd_conf_file());
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove hostapd.conf");
    }
    sleep(1);

#ifndef _OPENWRT_
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

    /* Test case teardown case */
    if (reset == RESET_TYPE_TEARDOWN) {
        /* Send hostapd log to Tool */
    }

    stop_loopback_data(NULL);

    if (reset == RESET_TYPE_INIT) {
        /* clean the log */
        system("rm -rf /var/log/hostapd.log >/dev/null 2>/dev/null");

#ifdef _WTS_OPENWRT_
        /* Reset uci configurations */
        snprintf(buffer, sizeof(buffer), "uci -q delete wireless.wifi0.country");
        system(buffer);

        snprintf(buffer, sizeof(buffer), "uci -q delete wireless.wifi1.country");
        system(buffer);

        system("uci -q delete wireless.@wifi-iface[0].own_ie_override");
        system("uci -q delete wireless.@wifi-iface[1].own_ie_override");
#endif
    }

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
#ifdef _WTS_OPENWRT_
    char wifi_name[16], band[16], country[16];
    int enable_n = 0, enable_ac = 0, enable_ax = 0;
    int channel = 0, ht40 = 0, chwidth = 0;
    char value[16], ie_override[256];
    int wlan_id = 0;

    memset(country, 0, sizeof(country));
    memset(ie_override, 0, sizeof(ie_override));
#endif

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

#ifdef _WTS_OPENWRT_
        if (tlv->id == TLV_HW_MODE) {
            memset(band, 0, sizeof(band));
            memcpy(band, tlv->value, tlv->len);
        }

        if (tlv->id == TLV_IEEE80211_N) {
            memset(value, 0, sizeof(value));
            memcpy(value, tlv->value, tlv->len);
            enable_n = atoi(value);
        }

        if (tlv->id == TLV_IEEE80211_AC) {
            memset(value, 0, sizeof(value));
            memcpy(value, tlv->value, tlv->len);
            enable_ac = atoi(value);
        }

        if (tlv->id == TLV_IEEE80211_AX) {
            memset(value, 0, sizeof(value));
            memcpy(value, tlv->value, tlv->len);
            enable_ax = atoi(value);
            continue;
        }

        if (tlv->id == TLV_CHANNEL) {
            memset(value, 0, sizeof(value));
            memcpy(value, tlv->value, tlv->len);
            channel = atoi(value);
        }

        if (tlv->id == TLV_HE_OPER_CHWIDTH || tlv->id == TLV_VHT_OPER_CHWIDTH) {
            memset(value, 0, sizeof(value));
            memcpy(value, tlv->value, tlv->len);
            chwidth = atoi(value);
        }

        if (tlv->id == TLV_HT_CAPB && strstr(tlv->value, "40")) {
            ht40 = 1;
        }

        if (tlv->id == TLV_COUNTRY_CODE) {
            memcpy(country, tlv->value, tlv->len);
            continue;
        }

        if (tlv->id == TLV_HE_MU_EDCA) {
            he_mu_edca = 1;
            continue;
        }

        if (tlv->id == TLV_IEEE80211_D || tlv->id == TLV_IEEE80211_H ||
            tlv->id == TLV_HE_OPER_CHWIDTH || tlv->id == TLV_HE_OPER_CENTR_FREQ)
            continue;

        if (tlv->id == TLV_IE_OVERRIDE) {
            memcpy(ie_override, tlv->value, tlv->len);
        }
#endif

        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, tlv->value, tlv->len);
        sprintf(cfg_item, "%s=%s\n", cfg->config_name, buffer);
        strcat(output, cfg_item);

        if (tlv->id == TLV_CONTROL_INTERFACE) {
            ctrl_iface = 1;
            memset(buffer, 0, sizeof(buffer));
            memcpy(buffer, tlv->value, tlv->len);
            set_hapd_ctrl_path(buffer);
        }
        if (tlv->id == TLV_HE_MU_EDCA)
            add_mu_edca_params(output);
    }
    if (ctrl_iface == 0) {
        indigo_logger(LOG_LEVEL_ERROR, "No Remote UDP ctrl interface TLV for TP");
        return 0;
    }

#ifdef _WTS_OPENWRT_
    if (!strncmp(band, "a", 1)) {
        snprintf(wifi_name, sizeof(wifi_name), "wifi0");
        wlan_id = 0;
        if (enable_ax) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11axa\'", wifi_name);
        } else if (enable_ac) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11ac\'", wifi_name);
        } else if (enable_n) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11na\'", wifi_name);
        } else {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11a\'", wifi_name);
        }
        system(buffer);

        if (enable_n) {
            if (chwidth == 2) {
                snprintf(buffer, sizeof(buffer), "uci set wireless.%s.htmode=\'HT160\'", wifi_name);
            } else if (chwidth == 0){
                if (ht40)
                    snprintf(buffer, sizeof(buffer), "uci set wireless.%s.htmode=\'HT40\'", wifi_name);
                else
                    snprintf(buffer, sizeof(buffer), "uci set wireless.%s.htmode=\'HT20\'", wifi_name);
            } else {
                snprintf(buffer, sizeof(buffer), "uci set wireless.%s.htmode=\'HT80\'", wifi_name);
            }
            system(buffer);
        }
    } else if (!strncmp(band, "b", 1)) {
        snprintf(wifi_name, sizeof(wifi_name), "wifi1");
        wlan_id = 1;
        snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11b\'", wifi_name);
        system(buffer);
    } else if (!strncmp(band, "g", 1)) {
        snprintf(wifi_name, sizeof(wifi_name), "wifi1");
        wlan_id = 1;
        if (enable_ax) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11axg\'", wifi_name);
        } else if (enable_n) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11ng\'", wifi_name);
        } else {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.hwmode=\'11g\'", wifi_name);
        }
        system(buffer);

        if (enable_n) {
            snprintf(buffer, sizeof(buffer), "uci set wireless.%s.htmode=\'HT20\'", wifi_name);
            system(buffer);
        }
    }
    if (strlen(country) > 0) {
        snprintf(buffer, sizeof(buffer), "uci set wireless.%s.country=\'%s\'", wifi_name, country);
        system(buffer);
    }
    snprintf(buffer, sizeof(buffer), "uci set wireless.%s.channel=\'%d\'", wifi_name, channel);
    system(buffer);
    if (strlen(ie_override) > 0) {
        sprintf(buffer, "uci set wireless.@wifi-iface[%d].own_ie_override=%s", wlan_id, ie_override);
        system(buffer);
    }

    system("uci commit");
#endif

    return strlen(output);
}

// ACK:  {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'ACK: Command received'} 
// RESP: {<IndigoResponseTLV.STATUS: 40961>: '0', <IndigoResponseTLV.MESSAGE: 40960>: 'DUT configured as AP : Configuration file created'} 
static int configure_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int band, len;
    char hw_mode_str[8];
    char buffer[L_BUFFER_LEN], ifname[S_BUFFER_LEN];
    char *message = "DUT configured as AP : Configuration file created";
    struct tlv_hdr *tlv;
    struct interface_info* wlan = NULL;

    /* Single wlan case */
    tlv = find_wrapper_tlv_by_id(req, TLV_HW_MODE);
    if (tlv) {
        memset(hw_mode_str, 0, sizeof(hw_mode_str));
        memcpy(hw_mode_str, tlv->value, tlv->len);
        if (!strncmp(hw_mode_str, "a", 1)) {
            band = BAND_5GHZ;
        } else {
            band = BAND_24GHZ;
        }
        set_default_wireless_interface_info(band);
    }
    strcpy(ifname, get_default_wireless_interface_info());

#ifdef _WTS_OPENWRT_
    /* Handle the platform dependency */
    tlv = find_wrapper_tlv_by_id(req, TLV_MBO);
    rrm = tlv ? 1 : 0;
#endif
    /* Generate the hostapd configuration and write to configuration */
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
    char buffer[S_BUFFER_LEN], g_ctrl_iface[64], log_level[TLV_VALUE_SIZE];
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

    /* TLV: DEBUG_LEVEL */
    tlv = find_wrapper_tlv_by_id(req, TLV_DEBUG_LEVEL);
    memset(log_level, 0, sizeof(log_level));
    if (tlv) {
        memcpy(log_level, tlv->value, tlv->len);
    }

    if (strlen(log_level)) {
        set_hostapd_debug_level(get_debug_level(atoi(log_level)));
    }

#ifdef _OPENWRT_
#ifdef _WTS_OPENWRT_
    // Apply radio configurations via native hostpad
    system("hostapd -g /var/run/hostapd/global -B -P /var/run/hostapd-global.pid");
    sleep(1);
    system("wifi down");
    sleep(2);
    system("wifi up");
    sleep(3);
    system("killall hostapd >/dev/null 2>/dev/null");
    sleep(2);

    // Apply runtime configuratoins before hostapd starts.
    // DFS wait again if apply this after hostapd starts.
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "cfg80211tool %s rrm %d", get_wireless_interface(), rrm);
    system(buffer);
    // Workaround for data IOT issue
    if (he_mu_edca == 0) {
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "cfg80211tool %s he_ul_ofdma 0", get_wireless_interface());
        system(buffer);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "cfg80211tool %s he_ul_mimo 0", get_wireless_interface());
        system(buffer);
    } else // Reset to Disable
        he_mu_edca = 0;
    // Avoid target assert during channel switch
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "cfg80211tool %s twt_responder 0", get_wireless_interface());
    system(buffer);
#endif
    sprintf(buffer, "hostapd-wfa -B -t -P /var/run/hostapd.pid -g %s %s -f /var/log/hostapd.log %s",
        g_ctrl_iface, get_hostapd_debug_arguments(), get_hapd_conf_file());
#else
    sprintf(buffer, "hostapd -B -t -P /var/run/hostapd.pid -g %s %s %s -f /var/log/hostapd.log",
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
    int len = 0;
    char buffer[64];
    struct tlv_hdr *tlv = NULL;
    char *ifname = NULL;
    char *message = TLV_VALUE_ASSIGN_STATIC_IP_OK;

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_STATIC_IP);
    if (tlv) {
        memcpy(buffer, tlv->value, tlv->len);
    } else {
        message = "Failed.";
        goto response;
    }

    ifname = get_wireless_interface();

    /* Release IP address from interface */
    reset_interface_ip(ifname);
    /* Bring up interface */
    control_interface(ifname, "up");
    /* Set IP address with network mask */
    strcat(buffer, "/24");
    len = set_interface_ip(get_wireless_interface(), buffer);
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

/* Tool will send this API to stop continuous data */
static int stop_loopback_data_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char recv_count[16], send_count[16];
    int recvd, sent;

    recvd = stop_loopback_data(&sent);
    indigo_logger(LOG_LEVEL_INFO, "Stop continuous loopdata data, send: %d receive: %d",
                  sent, recvd);
    snprintf(recv_count, sizeof(recv_count), "%d", recvd);
    snprintf(send_count, sizeof(send_count), "%d", sent);
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_LOOP_BACK_STOP_OK), TLV_VALUE_LOOP_BACK_STOP_OK);
    fill_wrapper_tlv_bytes(resp, TLV_LOOP_BACK_DATA_RECEIVED, strlen(recv_count), recv_count);
    fill_wrapper_tlv_bytes(resp, TLV_LOOP_BACK_DATA_SENT, strlen(send_count), send_count);

    return 0;
}

static int send_loopback_data_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct tlv_hdr *tlv;
    char dut_ip[64];
    char dut_port[32];
    char rate[16], pkt_count[16], pkt_size[16], recv_count[16];
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
    memset(dut_port, 0, sizeof(dut_port));
    tlv = find_wrapper_tlv_by_id(req, TLV_DUT_UDP_PORT);
    if (tlv) {
        memcpy(dut_port, tlv->value, tlv->len);
    } else {
        goto done;
    }

    memset(rate, 0, sizeof(rate));
    tlv = find_wrapper_tlv_by_id(req, TLV_UDP_PACKET_RATE);
    if (tlv) {
        memcpy(rate, tlv->value, tlv->len);
    } else {
        snprintf(rate, sizeof(rate), "1");
    }

    memset(pkt_count, 0, sizeof(pkt_count));
    tlv = find_wrapper_tlv_by_id(req, TLV_PACKET_COUNT);
    if (tlv) {
        memcpy(pkt_count, tlv->value, tlv->len);
    } else {
        snprintf(pkt_count, sizeof(pkt_count), "10");
    }

    memset(pkt_size, 0, sizeof(pkt_size));
    tlv = find_wrapper_tlv_by_id(req, TLV_UDP_PACKET_SIZE);
    if (tlv) {
        memcpy(pkt_size, tlv->value, tlv->len);
    } else {
        snprintf(pkt_size, sizeof(pkt_size), "1000");
    }

    /* Start loopback */
    snprintf(recv_count, sizeof(recv_count), "0");
    recvd = send_loopback_data(dut_ip, atoi(dut_port), atoi(pkt_count), atoi(pkt_size), atof(rate));
    /* -1 : Continuous data case uses timer and directly reply OK */
    if (recvd > 0 || atoi(pkt_count) == -1) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_SEND_LOOPBACK_DATA_OK;
        snprintf(recv_count, sizeof(recv_count), "%d", recvd);
    }
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    fill_wrapper_tlv_bytes(resp, TLV_LOOP_BACK_DATA_RECEIVED, strlen(recv_count), recv_count);

    return 0;
}

static int send_ap_arp_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct tlv_hdr *tlv;
    char target_ip[64];
    char rate[16], arp_count[16], recv_count[16];
    int status = TLV_VALUE_STATUS_NOT_OK, recvd = 0, send = 0;
    char *message = TLV_VALUE_BROADCAST_ARP_TEST_NOT_OK;

    /* TLV: TLV_ARP_TARGET_IP */
    memset(target_ip, 0, sizeof(target_ip));
    tlv = find_wrapper_tlv_by_id(req, TLV_ARP_TARGET_IP);
    if (tlv) {
        memcpy(target_ip, tlv->value, tlv->len);
    } else {
        goto done;
    }

    /* TLV: TLV_ARP_FRAME_COUNT */
    memset(arp_count, 0, sizeof(arp_count));
    tlv = find_wrapper_tlv_by_id(req, TLV_ARP_FRAME_COUNT);
    if (tlv) {
        memcpy(arp_count, tlv->value, tlv->len);
    } else {
        snprintf(arp_count, sizeof(arp_count), "2");
    }
    send = atoi(arp_count);

    /* TLV_ARP_TRANSMISSION_RATE */
    memset(rate, 0, sizeof(rate));
    tlv = find_wrapper_tlv_by_id(req, TLV_ARP_TRANSMISSION_RATE);
    if (tlv) {
        memcpy(rate, tlv->value, tlv->len);
    } else {
        snprintf(rate, sizeof(rate), "1");
    }

    /* Send broadcast ARP */
    memset(recv_count, 0, sizeof(recv_count));
    recvd = send_broadcast_arp(target_ip, &send, atoi(rate));
    snprintf(recv_count, sizeof(recv_count), "%d", recvd);
    if (send > 0) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_BROADCAST_ARP_TEST_OK;
    }
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    //fill_wrapper_tlv_byte(resp, TLV_ARP_SENT_NUM, send);
    fill_wrapper_tlv_bytes(resp, TLV_ARP_RECV_NUM, strlen(recv_count), recv_count);

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
    int len = 0, reset = 0;
    char buffer[S_BUFFER_LEN], reset_type[16];
    char *parameter[] = {"pidof", "wpa_supplicant", NULL};
    char *message = NULL;
    struct tlv_hdr *tlv = NULL;

    /* TLV: RESET_TYPE */
    tlv = find_wrapper_tlv_by_id(req, TLV_RESET_TYPE);
    memset(reset_type, 0, sizeof(reset_type));
    if (tlv) {
        memcpy(reset_type, tlv->value, tlv->len);
        reset = atoi(reset_type);
        indigo_logger(LOG_LEVEL_DEBUG, "Reset Type: %d", reset);
    }

    system("killall wpa_supplicant 1>/dev/null 2>/dev/null");
    sleep(2);

    len = unlink(get_wpas_conf_file());
    if (len) {
        indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove wpa_supplicant.conf");
    }
    sleep(1);

    /* Test case teardown case */
    if (reset == RESET_TYPE_TEARDOWN) {
        /* Send supplicant log to Tool */
    }

    if (reset == RESET_TYPE_INIT) {
        /* clean the log */
        system("rm -rf /var/log/supplicant.log >/dev/null 2>/dev/null");
    }

    len = reset_interface_ip(get_wireless_interface());
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
    int sae_only = 0;
    char port[16];
    struct tlv_hdr *tlv = NULL;

    struct tlv_to_config_name* cfg = NULL;

    tlv = find_wrapper_tlv_by_id(wrapper, TLV_CONTROL_INTERFACE);
    if (tlv) {
        memset(value, 0, sizeof(value));
        memcpy(value, tlv->value, tlv->len);
        set_wpas_ctrl_path(value);
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

    //printf("wrapper->tlv_num %d\n", wrapper->tlv_num);
    for (i = 0; i < wrapper->tlv_num; i++) {
        cfg = find_hostapd_config(wrapper->tlv[i]->id);
        //printf("id %d cfg->config_name %s\n", wrapper->tlv[i]->id, cfg->config_name);
        if (cfg && find_wpas_global_config_name(wrapper->tlv[i]->id) == NULL) {
            memset(value, 0, sizeof(value));
            memcpy(value, wrapper->tlv[i]->value, wrapper->tlv[i]->len);

            if ((wrapper->tlv[i]->id == TLV_IEEE80211_W) || (wrapper->tlv[i]->id == TLV_STA_IEEE80211_W)) {
                ieee80211w_configured = 1;
            }

            if (wrapper->tlv[i]->id == TLV_KEY_MGMT) {
                if (strstr(value, "WPA-PSK") && strstr(value, "SAE")) {
                    transition_mode_enabled = 1;
                }
                if (!strstr(value, "WPA-PSK") && strstr(value, "SAE")) {
                    sae_only = 1;
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

    if (ieee80211w_configured == 0) {
        if (transition_mode_enabled) {
            strcat(buffer, "ieee80211w=1\n");
        } else if (sae_only) {
            strcat(buffer, "ieee80211w=2\n");
        } else if (owe_configured) {
            strcat(buffer, "ieee80211w=2\n");
        }
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

    /* platform dependent commands */
    set_channel_width();
    set_phy_mode();

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, len > 0 ? TLV_VALUE_STATUS_OK : TLV_VALUE_STATUS_NOT_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int associate_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char *message = TLV_VALUE_WPA_S_START_UP_NOT_OK;
    char buffer[256], log_level[TLV_VALUE_SIZE];
    int len, status = TLV_VALUE_STATUS_NOT_OK;
    struct tlv_hdr *tlv = NULL;

    /* TLV: DEBUG_LEVEL */
    tlv = find_wrapper_tlv_by_id(req, TLV_DEBUG_LEVEL);
    memset(log_level, 0, sizeof(log_level));
    if (tlv) {
        memcpy(log_level, tlv->value, tlv->len);
    }

    if (strlen(log_level)) {
        set_wpas_debug_level(get_debug_level(atoi(log_level)));
    }

#ifdef _OPENWRT_
#else
    system("rfkill unblock wlan");
    sleep(1);
#endif

    system("killall wpa_supplicant >/dev/null 2>/dev/null");
    sleep(3);

    /* Start WPA supplicant */
    memset(buffer, 0 ,sizeof(buffer));
    sprintf(buffer, "wpa_supplicant -B -t -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
    indigo_logger(LOG_LEVEL_DEBUG, "%s", buffer);
    len = system(buffer);

    message = TLV_VALUE_WPA_S_START_UP_OK;
    status = TLV_VALUE_STATUS_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    return 0;
}

static int start_up_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_START_UP_NOT_OK;
    char buffer[S_BUFFER_LEN], freq_list[512], ssid[512], response[1024], log_level[TLV_VALUE_SIZE], value[TLV_VALUE_SIZE];
    int len, status = TLV_VALUE_STATUS_NOT_OK, i, freq_list_len, ssid_len;
    size_t resp_len;
    char *parameter[] = {"pidof", "wpa_supplicant", NULL};
    struct tlv_hdr *tlv = NULL;

#ifdef _OPENWRT_
#else
    system("rfkill unblock wlan");
    sleep(1);
#endif

    system("killall wpa_supplicant >/dev/null 2>/dev/null");
    sleep(3);

    tlv = find_wrapper_tlv_by_id(req, TLV_FREQ_LIST);
    memset(freq_list, 0, sizeof(freq_list));
    if (tlv) {
        memset(value, 0, sizeof(value));
        memcpy(value, tlv->value, tlv->len);
        freq_list_len = sprintf(freq_list, "freq_list=%s\n", value);
    }
    
    tlv = find_wrapper_tlv_by_id(req, TLV_SSID);
    memset(ssid, 0, sizeof(ssid));
    if (tlv) {
        memset(value, 0, sizeof(value));
        memcpy(value, tlv->value, tlv->len);
        ssid_len = sprintf(ssid, "network={\nssid=\"%s\"\nscan_ssid=1\nkey_mgmt=NONE\n}\n", value);
    }
    
    tlv = find_wrapper_tlv_by_id(req, TLV_CONTROL_INTERFACE);
    if (tlv) {
        memset(buffer, 0, sizeof(buffer));
        memset(value, 0, sizeof(value));
        memcpy(value, tlv->value, tlv->len);
        set_wpas_ctrl_path(value);
        sprintf(buffer, "ctrl_interface=%s\nap_scan=1\n", value);
        
        if (freq_list_len) {
            strcat(buffer, freq_list);
        }
        
        if (ssid_len) {
            strcat(buffer, ssid);
        }
        len = strlen(buffer);

        if (len) {
            write_file(get_wpas_conf_file(), buffer, len);
        }
    } else {
        return 0;
    }

    /* TLV: DEBUG_LEVEL */
    tlv = find_wrapper_tlv_by_id(req, TLV_DEBUG_LEVEL);
    memset(log_level, 0, sizeof(log_level));
    if (tlv) {
        memcpy(log_level, tlv->value, tlv->len);
    }

    if (strlen(log_level)) {
        set_wpas_debug_level(get_debug_level(atoi(log_level)));
    }

    /* Start WPA supplicant */
    memset(buffer, 0 ,sizeof(buffer));
    sprintf(buffer, "wpa_supplicant -B -t -c %s %s -i %s -f /var/log/supplicant.log", 
        get_wpas_conf_file(), get_wpas_debug_arguments(), get_wireless_interface());
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

static int set_sta_phy_mode_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[BUFFER_LEN];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;

    /* TLV: TLV_PHYMODE */
    memset(param_value, 0, sizeof(param_value));
    tlv = find_wrapper_tlv_by_id(req, TLV_PHYMODE);
    if (tlv) {
        memcpy(param_value, tlv->value, tlv->len);
        indigo_logger(LOG_LEVEL_ERROR, "PHY mode value: %s", param_value);
    } else {
        goto done;
    }

    sta_hw_config.phymode_isset = true;

    if (strcmp(param_value, "auto") == 0) {
        sta_hw_config.phymode = PHYMODE_AUTO;
        set_phy_mode();
    } else if (strcmp(param_value, "11bgn") == 0) {
        sta_hw_config.phymode = PHYMODE_11BGN;
    } else if (strcmp(param_value, "11bg") == 0) {
        sta_hw_config.phymode = PHYMODE_11BG;
    } else if (strcmp(param_value, "11b") == 0) {
        /* not supported */
        sta_hw_config.phymode = PHYMODE_11B;
    } else if (strcmp(param_value, "11a") == 0) {
        sta_hw_config.phymode = PHYMODE_11A;
    } else if (strcmp(param_value, "11na") == 0) {
        sta_hw_config.phymode = PHYMODE_11NA;
    } else if (strcmp(param_value, "11ac") == 0) {
        sta_hw_config.phymode = PHYMODE_11AC;
    } else if (strcmp(param_value, "11axg") == 0) {
        sta_hw_config.phymode = PHYMODE_11AXG;
    } else if (strcmp(param_value, "11axa") == 0) {
        sta_hw_config.phymode = PHYMODE_11AXA;
    } else {
        goto done;
    }

    /* Check response */
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int set_sta_channel_width_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[BUFFER_LEN];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;

    /* TLV: TLV_CHANNEL_WIDTH */
    memset(param_value, 0, sizeof(param_value));
    tlv = find_wrapper_tlv_by_id(req, TLV_CHANNEL_WIDTH);
    if (tlv) {
        memcpy(param_value, tlv->value, tlv->len);
        indigo_logger(LOG_LEVEL_ERROR, "channel width value: %s", param_value);
    } else {
        goto done;
    }

    sta_hw_config.chwidth_isset = true;

    if (strcmp(param_value, "auto") == 0) {
        sta_hw_config.chwidth = CHWIDTH_AUTO;
        set_channel_width();
    } else if (strcmp(param_value, "20") == 0) {
        sta_hw_config.chwidth = CHWIDTH_20;
    } else if (strcmp(param_value, "40") == 0) {
        sta_hw_config.chwidth = CHWIDTH_40;
    } else if (strcmp(param_value, "80") == 0) {
        sta_hw_config.chwidth = CHWIDTH_80;
    } else if (strcmp(param_value, "160") == 0) {
        sta_hw_config.chwidth = CHWIDTH_160;
    } else if (strcmp(param_value, "80plus80") == 0) {
        sta_hw_config.chwidth = CHWIDTH_80PLUS80;
    } else {
        goto done;
    }

    /* Check response */
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int set_sta_power_save_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_POWER_SAVE_NOT_OK;
    char buffer[BUFFER_LEN];
    char param_value[256], conf[8], result[8];
    struct tlv_hdr *tlv = NULL;
    FILE *fp;
    char *iface = 0;

    /* TLV: TLV_STA_POWER_SAVE */
    memset(param_value, 0, sizeof(param_value));
    tlv = find_wrapper_tlv_by_id(req, TLV_STA_POWER_SAVE);
    if (tlv) {
        memcpy(param_value, tlv->value, tlv->len);
        indigo_logger(LOG_LEVEL_DEBUG, "power save value: %s", param_value);
    } else {
        goto done;
    }

    /* Assemble wpa_supplicant command */
    memset(buffer, 0, sizeof(buffer));
    sprintf(conf, "%s", !strcmp(param_value, "False") ? "off" : "on");
    iface = get_wireless_interface();
    sprintf(buffer, "iw dev %s set power_save %s && iw dev %s get power_save", 
            iface, (char *)&conf, iface);
    indigo_logger(LOG_LEVEL_DEBUG, "cmd: %s", buffer);
    system(buffer);

    fp = popen(buffer, "r");
    if (fp == NULL)
        goto done;

    /* Power save output format: Power save: on */
    fscanf(fp, "%*s %*s %s", (char *)&result);
    pclose(fp);
    indigo_logger(LOG_LEVEL_DEBUG, "power save config: %s, result: %s", conf, result);

    /* Check response */
    if (!strcmp(conf, result)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_POWER_SAVE_OK;
    }

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}
