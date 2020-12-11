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
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "vendor_specific.h"
#include "utils.h"

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

#ifdef _TEST_PLATFORM_

/* Be invoked when start controlApp */
void vendor_init() {
#if defined(_OPENWRT_) && !defined(_WTS_OPENWRT_)
    char buffer[BUFFER_LEN];
    char mac_addr[S_BUFFER_LEN];
    
    /* Vendor: add codes to let ControlApp have full control of hostapd */
    /* Avoid hostapd being invoked by procd */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "/etc/init.d/wpad stop");
    system(buffer);

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw phy phy1 interface add ath1 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy1 interface add ath11 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath0 type managed >/dev/null 2>/dev/null");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath01 type managed >/dev/null 2>/dev/null");
    system(buffer);

    memset(mac_addr, 0, sizeof(mac_addr));
    get_mac_address(mac_addr, sizeof(mac_addr), "ath1");
    sprintf(buffer, "ifconfig ath1 down");
    system(buffer);
    mac_addr[16] = (char)'0';
    sprintf(buffer, "ifconfig ath1 hw ether %s", mac_addr);
    system(buffer);

    sprintf(buffer, "ifconfig ath11 down");
    system(buffer);
    mac_addr[16] = (char)'1';
    sprintf(buffer, "ifconfig ath11 hw ether %s", mac_addr);
    system(buffer);

    memset(mac_addr, 0, sizeof(mac_addr));
    get_mac_address(mac_addr, sizeof(mac_addr), "ath0");
    sprintf(buffer, "ifconfig ath0 down");
    system(buffer);
    mac_addr[16] = (char)'0';
    sprintf(buffer, "ifconfig ath0 hw ether %s", mac_addr);
    system(buffer);

    sprintf(buffer, "ifconfig ath01 down");
    system(buffer);
    mac_addr[16] = (char)'1';
    sprintf(buffer, "ifconfig ath01 hw ether %s", mac_addr);
    system(buffer);
    sleep(1);
#endif
}

extern struct sta_platform_config sta_hw_config;

static int set_he_channel_width(int chwidth) {
#define BUFFER_SIZE 512
    FILE *f_ptr, *f_tmp_ptr;
    char *path = "/lib/firmware/iwl-dbg-cfg.ini";
    char *tmp_path = "/lib/firmware/iwl-dbg-cfg-tmp.ini";
    char *he_ie_str = "he_phy_cap=";
    int is_found = 0;
    char buffer[BUFFER_SIZE];

    f_ptr  = fopen(path, "r");
    f_tmp_ptr = fopen(tmp_path, "w");    

    if (f_ptr == NULL || f_tmp_ptr == NULL) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open the files");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    while ((fgets(buffer, BUFFER_SIZE, f_ptr)) != NULL) {
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

int set_channel_width(int chwidth) {
    int ret = -1;
    if (sta_hw_config.chwidth_isset && 
        (sta_hw_config.phymode == PHYMODE_11AXA || 
            sta_hw_config.phymode == PHYMODE_11AXG || 
            sta_hw_config.phymode == PHYMODE_AUTO)) {
        ret = set_he_channel_width(sta_hw_config.chwidth);
    }
    sta_hw_config.chwidth_isset = false;

    return ret;
}

void reload_driver() {
    system("sudo modprobe -r iwlwifi;sudo modprobe iwlwifi");
    sleep(3);
}

void disable_11ax() {
    system("sudo modprobe -r iwlwifi;sudo modprobe iwlwifi disable_11ax=1");
    sleep(3);
}
#endif /* _TEST_PLATFORM_ */
