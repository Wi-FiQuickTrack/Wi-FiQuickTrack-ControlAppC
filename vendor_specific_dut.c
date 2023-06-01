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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "vendor_specific.h"
#include "utils.h"

#ifdef HOSTAPD_SUPPORT_MBSSID_WAR
extern int use_openwrt_wpad;
#endif

#if defined(_OPENWRT_)
int detect_third_radio() {
    FILE *fp;
    char buffer[BUFFER_LEN];
    int third_radio = 0;

    fp = popen("iw dev", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if (strstr(buffer, "phy#2"))
                third_radio = 1;
        }
        pclose(fp);
    }

    return third_radio;
}
#endif

void interfaces_init() {
#if defined(_OPENWRT_) && !defined(_WTS_OPENWRT_)
    char buffer[BUFFER_LEN];
    char mac_addr[S_BUFFER_LEN];
    int third_radio = 0;

    third_radio = detect_third_radio();

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw phy phy1 interface add ath1 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy1 interface add ath11 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath0 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath01 type managed >/dev/null 2>/dev/null");
    system(buffer);
    if (third_radio == 1) {
        sprintf(buffer, "iw phy phy2 interface add ath2 type managed >/dev/null 2>/dev/null");
        system(buffer);
        sprintf(buffer, "iw phy phy2 interface add ath21 type managed >/dev/null 2>/dev/null");
        system(buffer);
    }

    memset(mac_addr, 0, sizeof(mac_addr));
    get_mac_address(mac_addr, sizeof(mac_addr), "ath1");
    control_interface("ath1", "down");
    mac_addr[16] = (char)'0';
    set_mac_address("ath1", mac_addr);

    control_interface("ath11", "down");
    mac_addr[16] = (char)'1';
    set_mac_address("ath11", mac_addr);

    memset(mac_addr, 0, sizeof(mac_addr));
    get_mac_address(mac_addr, sizeof(mac_addr), "ath0");
    control_interface("ath0", "down");
    mac_addr[16] = (char)'0';
    set_mac_address("ath0", mac_addr);

    control_interface("ath01", "down");
    mac_addr[16] = (char)'1';
    set_mac_address("ath01", mac_addr);

    if (third_radio == 1) {
        memset(mac_addr, 0, sizeof(mac_addr));
        get_mac_address(mac_addr, sizeof(mac_addr), "ath2");
        control_interface("ath2", "down");
        mac_addr[16] = (char)'8';
        set_mac_address("ath2", mac_addr);

        control_interface("ath21", "down");
        mac_addr[16] = (char)'9';
        set_mac_address("ath21", mac_addr);
    }
    sleep(1);
#endif
}
/* Be invoked when start controlApp */
void vendor_init() {
#if defined(_OPENWRT_) && !defined(_WTS_OPENWRT_)
    char buffer[BUFFER_LEN];
    char mac_addr[S_BUFFER_LEN];

    /* Vendor: add codes to let ControlApp have full control of hostapd */
    /* Avoid hostapd being invoked by procd */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "/etc/init.d/wpad stop >/dev/null 2>/dev/null");
    system(buffer);

    interfaces_init();
#if HOSTAPD_SUPPORT_MBSSID
#ifdef HOSTAPD_SUPPORT_MBSSID_WAR
        system("cp /overlay/hostapd /usr/sbin/hostapd");
        use_openwrt_wpad = 0;
#endif
#endif
#endif
}

/* Be invoked when terminate controlApp */
void vendor_deinit() {
    char buffer[S_BUFFER_LEN];
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "killall %s 1>/dev/null 2>/dev/null", get_hapd_exec_file());
    system(buffer);
    sprintf(buffer, "killall %s 1>/dev/null 2>/dev/null", get_wpas_exec_file());
    system(buffer);
}

/* Called by reset_device_hander() */
void vendor_device_reset() {
#ifdef _WTS_OPENWRT_
    char buffer[S_BUFFER_LEN];

    /* Reset the country code */
    snprintf(buffer, sizeof(buffer), "uci -q delete wireless.wifi0.country");
    system(buffer);

    snprintf(buffer, sizeof(buffer), "uci -q delete wireless.wifi1.country");
    system(buffer);
#endif
#if HOSTAPD_SUPPORT_MBSSID
    /* interfaces may be destroyed by hostapd after done the MBSSID testing */
    interfaces_init();
#ifdef HOSTAPD_SUPPORT_MBSSID_WAR
    if (use_openwrt_wpad > 0) {
        system("cp /overlay/hostapd /usr/sbin/hostapd");
        use_openwrt_wpad = 0;
    }
#endif
#endif
}

#ifdef _OPENWRT_
void openwrt_apply_radio_config(void) {
    char buffer[S_BUFFER_LEN];

#ifdef _WTS_OPENWRT_
    // Apply radio configurations
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "%s -g /var/run/hostapd/global -B -P /var/run/hostapd-global.pid",
        get_hapd_full_exec_path());
    system(buffer);
    sleep(1);
    system("wifi down >/dev/null 2>/dev/null");
    sleep(2);
    system("wifi up >/dev/null 2>/dev/null");
    sleep(3);

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "killall %s 1>/dev/null 2>/dev/null", get_hapd_exec_file());
    system(buffer);
    sleep(2);
#endif
}
#endif

/* Called by configure_ap_handler() */
void configure_ap_enable_mbssid() {
#ifdef _WTS_OPENWRT_
    /*
     * the following uci commands need to reboot openwrt
     *    so it can not be configured by controlApp
     * 
     * Manually enable MBSSID on OpenWRT when need to test MBSSID
     * 
    system("uci set wireless.qcawifi=qcawifi");
    system("uci set wireless.qcawifi.mbss_ie_enable=1");
    system("uci commit");
    */
#elif defined(_OPENWRT_)
#ifdef HOSTAPD_SUPPORT_MBSSID_WAR
    system("cp /rom/usr/sbin/wpad /usr/sbin/hostapd");
    use_openwrt_wpad = 1;
#endif
#endif
}

void configure_ap_radio_params(char *band, char *country, int channel, int chwidth) {
#ifdef _WTS_OPENWRT
char buffer[S_BUFFER_LEN], wifi_name[16];

    if (!strncmp(band, "a", 1)) {
        snprintf(wifi_name, sizeof(wifi_name), "wifi0");
    } else {
        snprintf(wifi_name, sizeof(wifi_name), "wifi1");
    }

    if (strlen(country) > 0) {
        snprintf(buffer, sizeof(buffer), "uci set wireless.%s.country=\'%s\'", wifi_name, country);
        system(buffer);
    }

    snprintf(buffer, sizeof(buffer), "uci set wireless.%s.channel=\'%d\'", wifi_name, channel);
    system(buffer);

    if (!strncmp(band, "a", 1)) {
        if (channel == 165) { // Force 20M for CH 165
            snprintf(buffer, sizeof(buffer), "uci set wireless.wifi0.htmode=\'HT20\'");
        } else if (chwidth == 2) { // 160M test cases only
            snprintf(buffer, sizeof(buffer), "uci set wireless.wifi0.htmode=\'HT160\'");
        } else if (chwidth == 0) { // 11N only
            snprintf(buffer, sizeof(buffer), "uci set wireless.wifi0.htmode=\'HT40\'");
        } else { // 11AC or 11AX
            snprintf(buffer, sizeof(buffer), "uci set wireless.wifi0.htmode=\'HT80\'");
        }
        system(buffer);
    }

    system("uci commit");
#else
    (void) band;
    (void) country;
    (void) channel;
    (void) chwidth;
#endif
}

/* void (*callback_fn)(void *), callback of active wlans iterator
 *
 * Called by start_ap_handler() after invoking hostapd
 */
void start_ap_set_wlan_params(void *if_info) {
#ifdef _WTS_OPENWRT_
    char buffer[S_BUFFER_LEN];
    struct interface_info *wlan = (struct interface_info *) if_info;

    memset(buffer, 0, sizeof(buffer));
    /* Workaround: openwrt has IOT issue with intel AX210 AX mode */
    sprintf(buffer, "cfg80211tool %s he_ul_ofdma 0", wlan->ifname);
    system(buffer);
    /* Avoid target assert during channel switch */
    sprintf(buffer, "cfg80211tool %s he_ul_mimo 0", wlan->ifname);
    system(buffer);
    sprintf(buffer, "cfg80211tool %s twt_responder 0", wlan->ifname);
    system(buffer);

    printf("set_wlan_params: %s\n", buffer);
#else
    (void) if_info;
#endif
}

/* Return addr of P2P-device if there is no GO or client interface */
int get_p2p_mac_addr(char *mac_addr, size_t size) {
    FILE *fp;
    char buffer[S_BUFFER_LEN], *ptr, addr[32];
    int error = 1, match = 0;

    fp = popen("iw dev", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            ptr = strstr(buffer, "addr");
            if (ptr != NULL) {
                sscanf(ptr, "%*s %s", addr);
                while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                    ptr = strstr(buffer, "type");
                    if (ptr != NULL) {
                        ptr += 5;
                        if (!strncmp(ptr, "P2P-GO", 6) || !strncmp(ptr, "P2P-client", 10)) {
			                snprintf(mac_addr, size, "%s", addr);
                            error = 0;
                            match = 1;
                        } else if (!strncmp(ptr, "P2P-device", 10)) {
			                snprintf(mac_addr, size, "%s", addr);
                            error = 0;
                        }
                        break;
                    }
                }
                if (match)
                    break;
            }
        }
        pclose(fp);
    }

    return error;
}

/* Get the name of P2P Group(GO or Client) interface */
int get_p2p_group_if(char *if_name, size_t size) {
    FILE *fp;
    char buffer[S_BUFFER_LEN], *ptr, name[32];
    int error = 1;

    fp = popen("iw dev", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            ptr = strstr(buffer, "Interface");
            if (ptr != NULL) {
                sscanf(ptr, "%*s %s", name);
                while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                    ptr = strstr(buffer, "type");
                    if (ptr != NULL) {
                        ptr += 5;
                        if (!strncmp(ptr, "P2P-GO", 6) || !strncmp(ptr, "P2P-client", 10)) {
			                snprintf(if_name, size, "%s", name);
                            error = 0;
                        }
                        break;
                    }
                }
                if (!error)
                    break;
            }
        }
        pclose(fp);
    }

    return error;
}

/* "iw dev" doesn't show the name of P2P device. The naming rule is based on wpa_supplicant */
int get_p2p_dev_if(char *if_name, size_t size) {
    snprintf(if_name, size, "p2p-dev-%s", get_wireless_interface());

    return 0;
}

/* Append IP range config and start dhcpd */
void start_dhcp_server(char *if_name, char *ip_addr)
{
    char buffer[S_BUFFER_LEN];
    char ip_sub[32], *ptr;
    FILE *fp;

    /* Avoid using system dhcp server service
       snprintf(buffer, sizeof(buffer), "sed -i -e 's/INTERFACESv4=\".*\"/INTERFACESv4=\"%s\"/g' /etc/default/isc-dhcp-server", if_name);
       system(buffer);
       snprintf(buffer, sizeof(buffer), "systemctl restart isc-dhcp-server.service");
       system(buffer);
     */
    /* Sample command from isc-dhcp-server: dhcpd -user dhcpd -group dhcpd -f -4 -pf /run/dhcp-server/dhcpd.pid -cf /etc/dhcp/dhcpd.conf p2p-wlp2s0-0 */

    /* Avoid apparmor check because we manually start dhcpd */
    memset(ip_sub, 0, sizeof(ip_sub));
    ptr = strrchr(ip_addr, '.');
    memcpy(ip_sub, ip_addr, ptr - ip_addr);
    system("cp QT_dhcpd.conf /etc/dhcp/QT_dhcpd.conf");
    fp = fopen("/etc/dhcp/QT_dhcpd.conf", "a");
    if (fp) {
        snprintf(buffer, sizeof(buffer), "\nsubnet %s.0 netmask 255.255.255.0 {\n", ip_sub);
        fputs(buffer, fp);
        snprintf(buffer, sizeof(buffer), "    range %s.50 %s.200;\n", ip_sub, ip_sub);
        fputs(buffer, fp);
        fputs("}\n", fp);
        fclose(fp);
    }
    system("touch /var/lib/dhcp/dhcpd.leases_QT");
    snprintf(buffer, sizeof(buffer), "dhcpd -4 -cf /etc/dhcp/QT_dhcpd.conf -lf /var/lib/dhcp/dhcpd.leases_QT %s", if_name);
    system(buffer);
}

void stop_dhcp_server()
{
    /* system("systemctl stop isc-dhcp-server.service"); */
    system("killall dhcpd 1>/dev/null 2>/dev/null");
}

void start_dhcp_client(char *if_name)
{
    char buffer[S_BUFFER_LEN];

    snprintf(buffer, sizeof(buffer), "dhclient -4 %s &", if_name);
    system(buffer);
}

void stop_dhcp_client()
{
    system("killall dhclient 1>/dev/null 2>/dev/null");
}

wps_setting *p_wps_setting = NULL;
wps_setting customized_wps_settings_ap[AP_SETTING_NUM];
wps_setting customized_wps_settings_sta[STA_SETTING_NUM];

void save_wsc_setting(wps_setting *s, char *entry, int len)
{
    char *p = NULL;

    (void) len;

    p = strchr(entry, '\n');
    if (p)
        p++;
    else
        p = entry;

    sscanf(p, "%[^:]:%[^:]:%s", s->wkey, s->value, s->attr);
}

wps_setting* __get_wps_setting(int len, char *buffer, enum wps_device_role role)
{
    char *token = strtok(buffer , ",");
    wps_setting *s = NULL;
    int i = 0;

    (void) len;

    if (role == WPS_AP) {
        memset(customized_wps_settings_ap, 0, sizeof(customized_wps_settings_ap));
        p_wps_setting = customized_wps_settings_ap;
        while (token != NULL) {
            s = &p_wps_setting[i++];
            save_wsc_setting(s, token, strlen(token));
            token = strtok(NULL, ",");
        }
    } else {
        memset(customized_wps_settings_sta, 0, sizeof(customized_wps_settings_sta));
        p_wps_setting = customized_wps_settings_sta;
        while (token != NULL) {
            s = &p_wps_setting[i++];
            save_wsc_setting(s, token, strlen(token));
            token = strtok(NULL, ",");
        }
    }
    return p_wps_setting;
}

wps_setting* get_vendor_wps_settings(enum wps_device_role role)
{
    /*
     * Please implement the vendor proprietary function to get WPS OOB and required settings.
     * */
#define WSC_SETTINGS_FILE_AP "/tmp/wsc_settings_APUT"
#define WSC_SETTINGS_FILE_STA "/tmp/wsc_settings_STAUT"
    int len = 0;
    char pipebuf[S_BUFFER_LEN];
    char *parameter_ap[] = {"cat", WSC_SETTINGS_FILE_AP, NULL, NULL};
    char *parameter_sta[] = {"cat", WSC_SETTINGS_FILE_STA, NULL, NULL};

    memset(pipebuf, 0, sizeof(pipebuf));
    if (role == WPS_AP) {
        if (0 == access(WSC_SETTINGS_FILE_AP, F_OK)) {
            // use customized ap wsc settings
#ifdef _OPENWRT_
            len = pipe_command(pipebuf, sizeof(pipebuf), "/bin/cat", parameter_ap);
#else
            len = pipe_command(pipebuf, sizeof(pipebuf), "/usr/bin/cat", parameter_ap);
#endif
            if (len) {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings APUT:\n %s", pipebuf);
                return __get_wps_setting(len, pipebuf, WPS_AP);
            } else {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings APUT: no data");
            }
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "APUT: WPS Erorr. Failed to get settings.");
            return NULL;
        }
    } else {
        if (0 == access(WSC_SETTINGS_FILE_STA, F_OK)) {
            // use customized sta wsc settings
            len = pipe_command(pipebuf, sizeof(pipebuf), "/usr/bin/cat", parameter_sta);
            if (len) {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings STAUT:\n %s", pipebuf);
                return __get_wps_setting(len, pipebuf, WPS_STA);
            } else {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings STAUT: no data");
            }
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "STAUT: WPS Erorr. Failed to get settings.");
            return NULL;
        }
    }
}
