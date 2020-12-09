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

/* Be invoked when start controlApp */
void vendor_init() {
#if defined(_OPENWRT_) && !defined(_WTS_OPENWRT_)
    char buffer[BUFFER_LEN];
    char mac_addr[S_BUFFER_LEN];
    
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "iw phy phy1 interface add ath1 type managed");
    system(buffer);
    sprintf(buffer, "iw phy phy1 interface add ath11 type managed");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath0 type managed");
    system(buffer);
    sprintf(buffer, "iw phy phy0 interface add ath01 type managed");
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

#ifdef _OPENWRT_
void openwrt_apply_radio_config(void) {
    char buffer[S_BUFFER_LEN];
#ifdef _WTS_OPENWRT_
    // Apply radio configurations
    system("hostapd -g /var/run/hostapd/global -B -P /var/run/hostapd-global.pid");
    sleep(1);
    system("wifi down >/dev/null 2>/dev/null");
    sleep(2);
    system("wifi up >/dev/null 2>/dev/null");
    sleep(3);
    system("killall hostapd >/dev/null 2>/dev/null");
    sleep(2);
#endif
}
#endif

/* Called by configure_ap_handler() */
void configure_ap_enable_mbssid() {
#ifdef _OPENWRT_
    system("uci set wireless.qcawifi=qcawifi");
    system("uci set wireless.qcawifi.mbss_ie_enable=1");
    system("uci commit");
#endif
}

/* void (*callback_fn)(void *), callback of active wlans iterator
 *
 * Called by start_ap_handler() after invoking hostapd
 */
void start_ap_set_wlan_params(void *if_info) {
    char buffer[S_BUFFER_LEN];
    struct interface_info *wlan = (struct interface_info *) if_info;

    memset(buffer, 0, sizeof(buffer));
#ifdef _OPENWRT_
    /* Workaround: openwrt has IOT issue with intel AX210 AX mode */
    sprintf(buffer, "cfg80211tool %s he_ul_ofdma 0", wlan->ifname);
    system(buffer);
    /* Avoid target assert during channel switch */
    sprintf(buffer, "cfg80211tool %s he_ul_mimo 0", wlan->ifname);
    system(buffer);
    sprintf(buffer, "cfg80211tool %s twt_responder 0", wlan->ifname);
    system(buffer);
#endif
    printf("set_wlan_params: %s\n", buffer);
}
