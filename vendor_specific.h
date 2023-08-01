/* Copyright (c) 2020 Wi-Fi Alliance                                                */

/* Permission to use, copy, modify, and/or distribute this software for any         */
/* purpose with or without fee is hereby granted, provided that the above           */
/* copyright notice and this permission notice appear in all copies.                */

/* THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL                    */
/* WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                    */
/* WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL                     */
/* THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                       */
/* CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING                        */
/* FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF                       */
/* CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT                       */
/* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS                          */
/* SOFTWARE. */

#ifndef _VENDOR_SPECIFIC_
#define _VENDOR_SPECIFIC_  1

/* hostapd definitions */
#ifdef _DUT_
#ifdef _OPENWRT_ /* DUT & OpenWRT */
#define HAPD_EXEC_FILE_DEFAULT                      "/usr/sbin/hostapd"
#else /* DUT & Laptop */
#define HAPD_EXEC_FILE_DEFAULT                      "/usr/local/bin/WFA-Hostapd-Supplicant/hostapd"
#endif /* _OPENWRT_ */

#else /* Platform */
#ifdef _OPENWRT_ /* Platform & OpenWRT */
/* Only OpenWRT + Test Platform, the hostapd path is /usr/sbin/hostapd_udp. */
#define HAPD_EXEC_FILE_DEFAULT                      "/usr/sbin/hostapd_udp"
#else /* Platform & Laptop */
#define HAPD_EXEC_FILE_DEFAULT                      "/usr/local/bin/WFA-Hostapd-Supplicant/hostapd_udp"
#endif /* _OPENWRT_ */
#endif /* _DUT_ */
#define HAPD_CTRL_PATH_DEFAULT                      "/var/run/hostapd"
#define HAPD_GLOBAL_CTRL_PATH_DEFAULT               "/var/run/hostapd-global"
#define HAPD_LOG_FILE                               "/var/log/hostapd.log"

#ifdef _OPENWRT_
#define HAPD_CONF_FILE_DEFAULT                      "/tmp/hostapd.conf"
#define HAPD_CONF_FILE_DEFAULT_PATH                 "/tmp"
#define WPAS_CONF_FILE_DEFAULT                      "/tmp/wpa_supplicant.conf"
// 2(2.4G): first interface ath1, second interface ath11
// 5(5G): first interface ath0, second interface ath01
#define DEFAULT_APP_INTERFACES_PARAMS               "2:ath1,2:ath11,2:ath12,2:ath13,5:ath0,5:ath01,5:ath02,5:ath03"
#define DEFAULT_APP_6E_INTERFACES_PARAMS            "6:ath0,6:ath01,6:ath02,6:ath03,5:ath1,5:ath11,5:ath12,5:ath13,2:ath2,2:ath21,2:ath22,2:ath23"

#else
#define HAPD_CONF_FILE_DEFAULT                      "/etc/hostapd/hostapd.conf"
#define HAPD_CONF_FILE_DEFAULT_PATH                 "/etc/hostapd"
#define WPAS_CONF_FILE_DEFAULT                      "/etc/wpa_supplicant/wpa_supplicant.conf"
// d(2.4G or 5G):Single band can work on 2G or 5G: first interface wlan0, second interface wlan1
#define DEFAULT_APP_INTERFACES_PARAMS               "2:wlan0,2:wlan1,5:wlan0,5:wlan1"

#endif /* _OPENWRT_ */

/* wpa_supplicant definitions */
#ifdef _DUT_
#define WPAS_EXEC_FILE_DEFAULT                      "/usr/local/bin/WFA-Hostapd-Supplicant/wpa_supplicant"
#else /* Platform */
#define WPAS_EXEC_FILE_DEFAULT                      "/usr/local/bin/WFA-Hostapd-Supplicant/wpa_supplicant_udp"

#endif /* _DUT_ */
#define WPAS_CTRL_PATH_DEFAULT                      "/var/run/wpa_supplicant"
#define WPAS_GLOBAL_CTRL_PATH_DEFAULT               "/var/run/wpa_supplicant/global" // not use wpas global before
#define WPAS_LOG_FILE                               "/var/log/supplicant.log"

#define HS20_OSU_CLIENT "/usr/local/bin/WFA-Hostapd-Supplicant/hs20-osu-client"

#define WIRELESS_INTERFACE_DEFAULT                  "wlan0"
#define SERVICE_PORT_DEFAULT                        9004

/* Default bridge for wireless interfaces */
#define BRIDGE_WLANS                                "br-wlans"

#ifdef _WTS_OPENWRT_
#define HOSTAPD_SUPPORT_MBSSID 0
#else
/* hostapd support MBSSID with single hostapd conf
 * hostapd support "multiple_bssid" configuration
 */
#define HOSTAPD_SUPPORT_MBSSID 1

#define HOSTAPD_SUPPORT_MBSSID_WAR
#endif

/* Default DUT GO intent value */
#define P2P_GO_INTENT 7

#define DHCP_SERVER_IP "192.168.65.1"
void vendor_init();
void vendor_deinit();
void vendor_device_reset();

/**
 * wps settings retrieved with vendor-specific operations.
 */

#define WPS_OOB_SSID          "ssid"
#define WPS_OOB_AUTH_TYPE     "wpa_key_mgmt"
#define WPS_OOB_ENC_TYPE      "wpa_pairwise"
#define WPS_OOB_PSK           "wpa_passphrase"
#define WPS_OOB_WPA_VER       "wpa"
#define WPS_OOB_AP_PIN        "ap_pin"
#define WPS_OOB_STATE         "wps_state"
#define WPS_CONFIG            "config_methods"
#define WPS_DEV_NAME          "device_name"
#define WPS_DEV_TYPE          "device_type"
#define WPS_MANUFACTURER      "manufacturer"
#define WPS_MODEL_NAME        "model_name"
#define WPS_MODEL_NUMBER      "model_number"
#define WPS_SERIAL_NUMBER     "serial_number"

#define WPS_OOB_NOT_CONFIGURED  "1"
#define WPS_OOB_CONFIGURED      "2"

#define SUPPORTED_CONF_METHOD_AP "label keypad push_button virtual_push_button display virtual_display"
#define SUPPORTED_CONF_METHOD_STA "keypad push_button virtual_push_button display virtual_display"

#define WPS_OOB_ONLY "1"
#define WPS_COMMON "2"

enum wps_device_role {
    WPS_AP,
    WPS_STA
};

#define GROUP_NUM (3)
#define AP_SETTING_NUM (14)
#define STA_SETTING_NUM (6)

typedef struct _wps_setting {
    /* key-value for each setting pair */
    char wkey[64];
    char value[512];
    char attr[64];
} wps_setting;

#ifdef _TEST_PLATFORM_

/**
 * struct sta_driver_ops - Driver interface API wrapper definition
 *
 * This structure defines the API that each driver interface needs to implement
 * for indigo c control application. 
 */
struct sta_driver_ops {
    const char *name;
    int (*set_channel_width)(void);
    void (*set_phy_mode)(void);
};

extern const struct sta_driver_ops sta_driver_platform1_ops;
extern const struct sta_driver_ops sta_driver_platform2_ops;

/* Generic platform dependent APIs */
int set_channel_width();
void set_phy_mode();
#endif

#ifdef _OPENWRT_
void openwrt_apply_radio_config(void);
int detect_third_radio(void);
#endif

void create_sta_interface();
void delete_sta_interface();

void configure_ap_enable_mbssid();
void configure_ap_radio_params(char *band, char *country, int channel, int chwidth);
void start_ap_set_wlan_params(void *if_info);

#ifdef CONFIG_P2P
int get_p2p_mac_addr(char *mac_addr, size_t size);
int get_p2p_group_if(char *if_name, size_t size);
int get_p2p_dev_if(char *if_name, size_t size);
#endif /* End Of CONFIG_P2P */

void start_dhcp_server(char *if_name, char *ip_addr);
void stop_dhcp_server();
void start_dhcp_client(char *if_name);
void stop_dhcp_client();
wps_setting* get_vendor_wps_settings(enum wps_device_role);
#endif
