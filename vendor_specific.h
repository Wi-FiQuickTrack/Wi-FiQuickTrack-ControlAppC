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

#ifndef _VENDOR_SPECIFIC_
#define _VENDOR_SPECIFIC_  1

#define HAPD_CTRL_PATH_DEFAULT                      "/var/run/hostapd"
#define HAPD_GLOBAL_CTRL_PATH_DEFAULT               "/var/run/hostapd-global"
#ifdef _OPENWRT_
#define HAPD_CONF_FILE_DEFAULT                      "/tmp/hostapd.conf"
#define HAPD_CONF_FILE_DEFAULT_PATH                 "/tmp"
#else
#define HAPD_CONF_FILE_DEFAULT                      "/etc/hostapd/hostapd.conf"
#define HAPD_CONF_FILE_DEFAULT_PATH                 "/etc/hostapd/"
#endif /* _OPENWRT_ */
#define WPAS_CTRL_PATH_DEFAULT                      "/var/run/wpa_supplicant"
#define WPAS_GLOBAL_CTRL_PATH_DEFAULT               "/var/run/wpa_supplicant/global" // not use wpas global before
#ifdef _OPENWRT_
#define WPAS_CONF_FILE_DEFAULT                      "/tmp/wpa_supplicant.conf"
#else
#define WPAS_CONF_FILE_DEFAULT                      "/etc/wpa_supplicant/wpa_supplicant.conf"
#endif /* _OPENWRT_ */
#define WIRELESS_INTERFACE_DEFAULT                  "wlan0"
#define SERVICE_PORT_DEFAULT                        9004

#define BRIDGE_WLANS                                "br-wlans"

#ifdef _TEST_PLATFORM_
int set_channel_width(int chwidth);
void reload_driver();
void disable_11ax();
#endif

#ifdef _OPENWRT_
void openwrt_apply_radio_config(void);
#endif

void configure_ap_enable_mbssid();
void start_ap_set_wlan_params(void *if_info);

#endif