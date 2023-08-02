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

#ifdef _TEST_PLATFORM_
extern struct sta_platform_config sta_hw_config;
const struct sta_driver_ops *sta_drv_ops = NULL;

/* Detect the STA driver from lspci Network Controller description */
const char *desc_platform1 = "Intel Corporation Device 2725";
const char *desc_platform2 = "Qualcomm Device 1101";

static void check_platform1_default_conf();

/**
 * Generic platform dependent API implementation 
 */

/* support multiple STA platforms detection */
void detect_sta_vendor() {
    char cmd[S_BUFFER_LEN];
    char buf[S_BUFFER_LEN];
    char *strbuf = NULL, *temp = NULL;
    int len = 0;
    int size = 1;
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "lspci |grep \"Network controller\"");

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        len = strlen(buf);
        temp = realloc(strbuf, size + len);
        if (temp == NULL) {
            return;
        } else {
            strbuf = temp;
        }
        strcpy(strbuf + size - 1, buf);
        size += len;
    }

    indigo_logger(LOG_LEVEL_INFO, "Device: %s", strbuf);

    if (strbuf && strstr(strbuf, desc_platform1)) {
        sta_drv_ops = &sta_driver_platform1_ops;
        indigo_logger(LOG_LEVEL_INFO, "hook platform handlers for platform 1");

        check_platform1_default_conf();
    } else if (strbuf && strstr(strbuf, desc_platform2)) {
        sta_drv_ops = &sta_driver_platform2_ops;
        indigo_logger(LOG_LEVEL_INFO, "hook platform handlers for platform 2");
    } else {
        /* set to platform 1 by default */
        sta_drv_ops = &sta_driver_platform1_ops;
        indigo_logger(LOG_LEVEL_INFO, 
            "Unable to find any supported drivers, hook the default platform handlers");
    }

    pclose(fp);
    free(strbuf);
}

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
    sprintf(buffer, "iw phy phy1 interface add ath12 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy1 interface add ath13 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath0 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath01 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath02 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath03 type managed >/dev/null 2>/dev/null");
    system(buffer);
    if (third_radio == 1) {
        sprintf(buffer, "iw phy phy2 interface add ath2 type managed >/dev/null 2>/dev/null");
        system(buffer);
        sprintf(buffer, "iw phy phy2 interface add ath21 type managed >/dev/null 2>/dev/null");
        system(buffer);
        sprintf(buffer, "iw phy phy2 interface add ath22 type managed >/dev/null 2>/dev/null");
        system(buffer);
        sprintf(buffer, "iw phy phy2 interface add ath23 type managed >/dev/null 2>/dev/null");
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

    control_interface("ath12", "down");
    mac_addr[16] = (char)'2';
    set_mac_address("ath12", mac_addr);

    control_interface("ath13", "down");
    mac_addr[16] = (char)'3';
    set_mac_address("ath13", mac_addr);

    memset(mac_addr, 0, sizeof(mac_addr));
    get_mac_address(mac_addr, sizeof(mac_addr), "ath0");
    control_interface("ath0", "down");
    mac_addr[16] = (char)'0';
    set_mac_address("ath0", mac_addr);

    control_interface("ath01", "down");
    mac_addr[16] = (char)'1';
    set_mac_address("ath01", mac_addr);

    control_interface("ath02", "down");
    mac_addr[16] = (char)'2';
    set_mac_address("ath02", mac_addr);

    control_interface("ath03", "down");
    mac_addr[16] = (char)'3';
    set_mac_address("ath03", mac_addr);

    if (third_radio == 1) {
        memset(mac_addr, 0, sizeof(mac_addr));
        get_mac_address(mac_addr, sizeof(mac_addr), "ath2");
        control_interface("ath2", "down");
        mac_addr[16] = (char)'8';
        set_mac_address("ath2", mac_addr);

        control_interface("ath21", "down");
        mac_addr[16] = (char)'9';
        set_mac_address("ath21", mac_addr);

        control_interface("ath22", "down");
        mac_addr[16] = (char)'A';
        set_mac_address("ath22", mac_addr);

        control_interface("ath23", "down");
        mac_addr[16] = (char)'B';
        set_mac_address("ath23", mac_addr);
    }
    sleep(1);
#endif
}

void create_sta_interface() {
    char buffer[S_BUFFER_LEN];

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw phy phy0 interface add %s_sta type managed >/dev/null 2>/dev/null", get_wireless_interface());
    system(buffer);
}

void delete_sta_interface() {
    char buffer[S_BUFFER_LEN];

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw dev %s_sta del", get_wireless_interface());
    system(buffer);
}

/* Be invoked when start controlApp */
void vendor_init() {
    /* Make sure native hostapd/wpa_supplicant is inactive */
    system("killall hostapd 1>/dev/null 2>/dev/null");
    sleep(1);
    system("killall wpa_supplicant 1>/dev/null 2>/dev/null");
    sleep(1);

#if defined(_OPENWRT_) && !defined(_WTS_OPENWRT_)
    char buffer[BUFFER_LEN];
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
#else
    detect_sta_vendor();
#endif
}

/* Be invoked when terminate controlApp */
void vendor_deinit() {
    char buffer[S_BUFFER_LEN];
    memset(buffer, 0, sizeof(buffer));
    system("killall hostapd >/dev/null 2>/dev/null");
#ifdef _OPENWRT_
    system("killall hostapd-wfa >/dev/null 2>/dev/null");
#endif
    sprintf(buffer, "killall %s 1>/dev/null 2>/dev/null", get_wpas_exec_file());
    system(buffer);
}

#ifdef CONFIG_AP
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
#endif /* End Of CONFIG_AP */

int set_channel_width() {
    int ret = -1;

    if (!sta_hw_config.chwidth_isset) {
        return 0;
    } else {
        if (sta_drv_ops && sta_drv_ops->set_channel_width != NULL) {
            ret = sta_drv_ops->set_channel_width();
        }
    }

    sta_hw_config.chwidth_isset = false;
    return ret;
}

void set_phy_mode() {
    if (!sta_hw_config.phymode_isset) {
        return;
    } else {
        if (sta_drv_ops && sta_drv_ops->set_phy_mode != NULL) {
            sta_drv_ops->set_phy_mode();
        }        
    }

    /* reset the flag for phymode */
    sta_hw_config.phymode_isset = false;
}

/**
 * Platform-dependent implementation for STA platform 1 
 */

struct he_chwidth_config {
    int chwidth;
    char config[32];
};

struct he_chwidth_config he_chwidth_config_list[] = {
    { CHWIDTH_AUTO, "" },
    { CHWIDTH_20, "003fc200fd09800ecffe00" },
    { CHWIDTH_40, "043fc200fd09800ecffe00" },
    { CHWIDTH_80, "043fc200fd09800ecffe00" },
    { CHWIDTH_80PLUS80, "1c3fc200fd09800ecffe00" },
    { CHWIDTH_160, "0c3fc200fd09800ecffe00" }
};

static void check_platform1_default_conf() {
    char *fname = "/lib/firmware/iwl-dbg-cfg.ini";
    char buffer[S_BUFFER_LEN];
    FILE *f_ptr = NULL;

    /* create default ini file if it doesn't exist */
    if (access(fname, F_OK) != 0) {
        f_ptr = fopen(fname, "w");
        if (f_ptr == NULL) {
            indigo_logger(LOG_LEVEL_ERROR, "Failed to create %s", fname);
            return;
        }

        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "[IWL DEBUG CONFIG DATA]\n");
        fputs(buffer, f_ptr);

        fclose(f_ptr);
    }
}

static void disable_11ax() {
    system("sudo modprobe -r iwlwifi;sudo modprobe iwlwifi disable_11ax=1");
    sleep(3);
}

static void reload_driver() {
    system("sudo modprobe -r iwlwifi;sudo modprobe iwlwifi");
    sleep(3);
}

static int set_he_channel_width(int chwidth) {
    FILE *f_ptr = NULL, *f_tmp_ptr = NULL;
    char *path = "/lib/firmware/iwl-dbg-cfg.ini";
    char *tmp_path = "/lib/firmware/iwl-dbg-cfg-tmp.ini";
    char *he_ie_str = "he_phy_cap=";
    int is_found = 0;
    char buffer[S_BUFFER_LEN];

    f_ptr  = fopen(path, "r");
    f_tmp_ptr = fopen(tmp_path, "w");    

    if (f_ptr == NULL || f_tmp_ptr == NULL) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open the files");
        if (f_ptr) {
            fclose(f_ptr);
        }
        if (f_tmp_ptr) {
            fclose(f_tmp_ptr);
        }
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    while ((fgets(buffer, S_BUFFER_LEN, f_ptr)) != NULL) {
        if (strstr(buffer, he_ie_str) != NULL) {
            is_found = 1;
            if (chwidth == CHWIDTH_AUTO) {
                indigo_logger(LOG_LEVEL_DEBUG, "clean he_phy_cap setting in auto mode");
                continue;
            } else {
                memset(buffer, 0, sizeof(buffer));
                snprintf(buffer, sizeof(buffer), "%s%s", 
                    he_ie_str, he_chwidth_config_list[chwidth].config);            
                indigo_logger(LOG_LEVEL_DEBUG, 
                    "replace he_phy_cap setting[%d]:%s\n", chwidth, buffer);
            }
        }

        fputs(buffer, f_tmp_ptr);
    }

    if (is_found == 0 && chwidth != CHWIDTH_AUTO) {
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "%s%s", 
                he_ie_str, he_chwidth_config_list[chwidth].config);
        indigo_logger(LOG_LEVEL_DEBUG, 
                    "set he_phy_cap setting:%s\n", buffer);        
        fputs(buffer, f_tmp_ptr);
    }

    fclose(f_ptr);
    fclose(f_tmp_ptr);

    /* replace original file with new file */
    remove(path);
    rename(tmp_path, path);

    /* reload the driver */
    reload_driver();
    return 0;
}

static int set_channel_width_platform1() {
    int ret = 0;
    if ((sta_hw_config.phymode == PHYMODE_11AXA || 
            sta_hw_config.phymode == PHYMODE_11AXG || 
            sta_hw_config.phymode == PHYMODE_AUTO)) {
        ret = set_he_channel_width(sta_hw_config.chwidth);
    } else if ((sta_hw_config.chwidth == CHWIDTH_20 &&
        (sta_hw_config.phymode == PHYMODE_11BGN || sta_hw_config.phymode == PHYMODE_11NA))) {
        ret = insert_wpa_network_config("disable_ht40=1\n");
    }

    return ret;
}

static void set_phy_mode_platform1() {
    if (sta_hw_config.phymode == PHYMODE_11BGN || sta_hw_config.phymode == PHYMODE_11AC) {
        disable_11ax();
    } else if (sta_hw_config.phymode == PHYMODE_11BG || sta_hw_config.phymode == PHYMODE_11A) {
        insert_wpa_network_config("disable_ht=1\n");
        disable_11ax();
    } else if (sta_hw_config.phymode == PHYMODE_11NA) {
        insert_wpa_network_config("disable_vht=1\n");
        disable_11ax();
    } else if (sta_hw_config.phymode == PHYMODE_11AXG || 
        sta_hw_config.phymode == PHYMODE_11AXA || sta_hw_config.phymode == PHYMODE_AUTO) {
        reload_driver();
    }
}


/**
 * Platform-dependent implementation for STA platform 2
 */

static int set_channel_width_platform2() {
    int ret = 0;
    if ((sta_hw_config.phymode == PHYMODE_11AXA || 
            sta_hw_config.phymode == PHYMODE_11AXG || 
            sta_hw_config.phymode == PHYMODE_AUTO)) {
        /* HE channel width setting */
    } else if ((sta_hw_config.chwidth == CHWIDTH_20 &&
        (sta_hw_config.phymode == PHYMODE_11BGN || sta_hw_config.phymode == PHYMODE_11NA))) {
        ret = insert_wpa_network_config("disable_ht40=1\n");
    }

    return ret;
}

static void set_phy_mode_platform2() {
    if (sta_hw_config.phymode == PHYMODE_11BGN || sta_hw_config.phymode == PHYMODE_11AC) {
        /* disable HE */
    } else if (sta_hw_config.phymode == PHYMODE_11BG || sta_hw_config.phymode == PHYMODE_11A) {
        insert_wpa_network_config("disable_ht=1\n");
    } else if (sta_hw_config.phymode == PHYMODE_11NA) {
        insert_wpa_network_config("disable_vht=1\n");
    } else if (sta_hw_config.phymode == PHYMODE_11AXG || 
        sta_hw_config.phymode == PHYMODE_11AXA || sta_hw_config.phymode == PHYMODE_AUTO) {
        /* reset to HE */
    }
}

const struct sta_driver_ops sta_driver_platform1_ops = {
	.name			        = "platform1",
	.set_channel_width      = set_channel_width_platform1,
	.set_phy_mode           = set_phy_mode_platform1,    
};


const struct sta_driver_ops sta_driver_platform2_ops = {
	.name			        = "platform2",
	.set_channel_width      = set_channel_width_platform2,
	.set_phy_mode           = set_phy_mode_platform2,
};

#ifdef CONFIG_P2P
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
#endif /* End Of CONFIG_P2P */

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

wps_setting wps_settings_ap[GROUP_NUM][AP_SETTING_NUM] = {
    {
        /*
        * WPS OOB required. (Not-Configured OOB state)
        * */
        { WPS_OOB_SSID, "Openwrt-WPS-tp", WPS_OOB_ONLY }, /* ap broadcasts ssid */
        { WPS_OOB_AUTH_TYPE, "WPA-PSK", WPS_OOB_ONLY }, /* authentication type */
        { WPS_OOB_ENC_TYPE, "CCMP", WPS_OOB_ONLY }, /* encryption type */
        { WPS_OOB_WPA_VER, "2", WPS_OOB_ONLY }, /* wpa version. 1: wpa, 2: wpa2 */
        { WPS_OOB_PSK, "1qaz2wsx", WPS_OOB_ONLY }, /* passphrass */
        { WPS_OOB_STATE, WPS_OOB_NOT_CONFIGURED, WPS_OOB_ONLY }, /* wps oob state */
        /*
        * General
        * */
        { WPS_OOB_AP_PIN, "12345670", WPS_COMMON }, /* wps ap pin */
        { WPS_CONFIG, SUPPORTED_CONF_METHOD_AP, WPS_COMMON }, /* config methods */
        { WPS_DEV_NAME, "Openwrt Wireless AP", WPS_COMMON }, /* device name  */
        { WPS_DEV_TYPE, "6-0050F204-1", WPS_COMMON }, /* primary device type */
        { WPS_MANUFACTURER, "OpenwrtProject.org", WPS_COMMON }, /* manufacturer */
        { WPS_MODEL_NAME, "Openwrt Wireless AP", WPS_COMMON }, /* model name */
        { WPS_MODEL_NUMBER, "Openwrt Wireless AP-001", WPS_COMMON }, /* model number */
        { WPS_SERIAL_NUMBER, "OA14998888", WPS_COMMON }, /* serial number */
    },
    {
        /*
        * WPS OOB required. (Not-Configured OOB state) - Test purpose for WPS IE fragmentation.
        * */
        { WPS_OOB_SSID, "Openwrt-WPS-tp", WPS_OOB_ONLY }, /* ap broadcasts ssid */
        { WPS_OOB_AUTH_TYPE, "WPA-PSK", WPS_OOB_ONLY }, /* authentication type */
        { WPS_OOB_ENC_TYPE, "CCMP", WPS_OOB_ONLY }, /* encryption type */
        { WPS_OOB_WPA_VER, "2", WPS_OOB_ONLY }, /* wpa version. 1: wpa, 2: wpa2 */
        { WPS_OOB_PSK, "1qaz2wsx", WPS_OOB_ONLY }, /* passphrass */
        { WPS_OOB_STATE, WPS_OOB_NOT_CONFIGURED, WPS_OOB_ONLY }, /* wps oob state */
        /*
        * General
        * */
        { WPS_OOB_AP_PIN, "12345670", WPS_COMMON }, /* wps ap pin */
        { WPS_CONFIG, SUPPORTED_CONF_METHOD_AP, WPS_COMMON }, /* config methods */
        { WPS_DEV_NAME, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* device name  */
        { WPS_DEV_TYPE, "6-0050F204-1", WPS_COMMON }, /* primary device type */
        { WPS_MANUFACTURER, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", WPS_COMMON }, /* manufacturer */
        { WPS_MODEL_NAME, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* model name */
        { WPS_MODEL_NUMBER, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* model number */
        { WPS_SERIAL_NUMBER, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* serial number */
    },
    {
        /*
        * WPS OOB required. (Configured OOB state)
        * */
        { WPS_OOB_SSID, "Openwrt-WPS-tp", WPS_OOB_ONLY }, /* ap broadcasts ssid */
        { WPS_OOB_AUTH_TYPE, "WPA-PSK", WPS_OOB_ONLY }, /* authentication type */
        { WPS_OOB_ENC_TYPE, "CCMP", WPS_OOB_ONLY }, /* encryption type */
        { WPS_OOB_WPA_VER, "2", WPS_OOB_ONLY }, /* wpa version. 1: wpa, 2: wpa2 */
        { WPS_OOB_PSK, "1qaz2wsx", WPS_OOB_ONLY }, /* passphrass */
        { WPS_OOB_STATE, WPS_OOB_CONFIGURED, WPS_OOB_ONLY }, /* wps oob state */
        /*
        * General
        * */
        { WPS_OOB_AP_PIN, "12345670", WPS_COMMON }, /* wps ap pin */
        { WPS_CONFIG, SUPPORTED_CONF_METHOD_AP, WPS_COMMON }, /* config methods */
        { WPS_DEV_NAME, "Openwrt Wireless AP", WPS_COMMON }, /* device name  */
        { WPS_DEV_TYPE, "6-0050F204-1", WPS_COMMON }, /* primary device type */
        { WPS_MANUFACTURER, "OpenwrtProject.org", WPS_COMMON }, /* manufacturer */
        { WPS_MODEL_NAME, "Openwrt Wireless AP", WPS_COMMON }, /* model name */
        { WPS_MODEL_NUMBER, "Openwrt Wireless AP-001", WPS_COMMON }, /* model number */
        { WPS_SERIAL_NUMBER, "OA14998888", WPS_COMMON }, /* serial number */
    },
};

wps_setting wps_settings_sta[GROUP_NUM][STA_SETTING_NUM] = {
    {
        /*
        * General
        * */
        { WPS_CONFIG, SUPPORTED_CONF_METHOD_STA, WPS_COMMON }, /* config methods */
        { WPS_DEV_NAME, "Intel Wireless STA", WPS_COMMON }, /* device name  */
        { WPS_MANUFACTURER, "Intel.com", WPS_COMMON }, /* manufacturer */
        { WPS_MODEL_NAME, "Intel Wireless STA", WPS_COMMON }, /* model name */
        { WPS_MODEL_NUMBER, "Intel Wireless STA-001", WPS_COMMON }, /* model number */
        { WPS_SERIAL_NUMBER, "STA-001", WPS_COMMON }, /* serial number */
    },
    {
        /*
        * Test purpose for WPS IE fragmentation.
        * */
        { WPS_CONFIG, SUPPORTED_CONF_METHOD_STA, WPS_COMMON }, /* config methods */
        { WPS_DEV_NAME, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* device name  */
        { WPS_MANUFACTURER, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890", WPS_COMMON }, /* manufacturer */
        { WPS_MODEL_NAME, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* model name */
        { WPS_MODEL_NUMBER, "1234567890abcdef1234567890abcdef", WPS_COMMON }, /* model number */
        { WPS_SERIAL_NUMBER, "001", WPS_COMMON }, /* serial number */
    },
    {
        {0}
    }
};

wps_setting* get_vendor_wps_settings(enum wps_device_role role)
{
    if (role == WPS_AP)
        return wps_settings_ap[0];
    else
        return wps_settings_sta[0];
}

wps_setting* get_vendor_wps_settings_for_ie_frag_test(enum wps_device_role role)
{
    /*
    * Test purpose to enlarge wps ie payload and perform wps ie fragmentation automatically.
    * */

    if (role == WPS_AP)
        return wps_settings_ap[1];
    else if (role == WPS_STA)
        return wps_settings_sta[1];
    else
        return NULL;
}
#endif /* _TEST_PLATFORM_ */
