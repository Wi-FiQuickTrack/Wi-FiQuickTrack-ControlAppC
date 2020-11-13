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

#ifndef _INDIGO_UTILS_
#define _INDIGO_UTILS_  1

#define S_BUFFER_LEN              256
#define BUFFER_LEN                1536
#define L_BUFFER_LEN              8192

/* Log */
enum {
    LOG_LEVEL_DEBUG_VERBOSE = 0,    
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_NOTICE = 3,
    LOG_LEVEL_WARNING = 4,
    LOG_LEVEL_ERROR = 5
};

void indigo_logger(int level, const char *fmt, ...);
int pipe_command(char *buffer, int buffer_size, char *cmd, char *parameter[]);
char* read_file(char *fn);
int write_file(char *fn, char *buffer, int len);

int get_mac_address(char *buffer, int size, char *interface);
int find_interface_ip(char *ipaddr, int ipaddr_len, char *name);
int loopback_client_start(char *target_ip, int target_port, char *local_ip, int local_port, int timeout);
int loopback_client_stop();
int loopback_client_status();
int send_loopback_data(char *target_ip, int target_port, int packet_count, int packet_size, int rate);
int send_broadcast_arp(char *target_ip, int *send_count, int rate);

int is_bridge_created();
int create_bridge(char *br);
int add_interface_to_bridge(char *br, char *interface);
int reset_bridge(char *br);
int control_interface(char *ifname, char *op);
int set_interface_ip(char *ifname, char *ip);
int add_wireless_interface(char *ifname);
int delete_wireless_interface(char *ifname);

#define HAPD_CTRL_PATH_DEFAULT                      "/var/run/hostapd"
#define HAPD_GLOBAL_CTRL_PATH_DEFAULT               "/var/run/hostapd-global"
#ifdef _OPENWRT_
#define HAPD_CONF_FILE_DEFAULT                      "/tmp/hostapd.conf"
#else
#define HAPD_CONF_FILE_DEFAULT                      "/etc/hostapd/hostapd.conf"
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

char* get_hapd_ctrl_path();
int set_hapd_ctrl_path(char* path);
char* get_hapd_global_ctrl_path();
int set_hapd_global_ctrl_path(char* path);
char* get_hapd_conf_file();
int set_hapd_conf_file(char* path);

char* get_wpas_ctrl_path();
int set_wpas_ctrl_path(char* path);
char* get_wpas_global_ctrl_path();
int set_wpas_global_ctrl_path(char* path);
char* get_wpas_conf_file();
int set_wpas_conf_file(char* path);

char* get_wireless_interface();
int set_wireless_interface(char *name);
int get_service_port();
int set_service_port(int port);
char* get_default_wireless_interface_info();
struct interface_info* get_wireless_interface_info_by_band(int band);

size_t strlcpy(char *dest, const char *src, size_t siz);
int get_key_value(char *value, char *buffer, char *token);


enum {
    BAND_24GHZ = 0,
    BAND_5GHZ = 1,
    BAND_DUAL = 2
};

struct channel_info {
    int channel;
    int freq;
};

struct interface_info {
    int band;
    int bssid;
    char ifname[16];
    char ssid[64];
};

int verify_band_from_freq(int freq, int band);

#endif
