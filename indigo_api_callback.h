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

#ifndef _INDIGO_API_CALLBACK
#define _INDIGO_API_CALLBACK


#define LOOPBACK_TIMEOUT 30


struct tlv_to_config_name {
    unsigned short tlv_id;
    char config_name[NAME_SIZE];
    int quoted;
};

struct tlv_to_config_name maps[] = {
    /* hapds */
    { TLV_SSID, "ssid", 0 },
    { TLV_CHANNEL, "channel", 0 },
    { TLV_WEP_KEY0, "wep_key0", 0 },
    { TLV_HW_MODE, "hw_mode", 0 },
    { TLV_AUTH_ALGORITHM, "auth_algs", 0 },
    { TLV_WEP_DEFAULT_KEY, "wep_default_key", 0 },
    { TLV_IEEE80211_D, "ieee80211d", 0 },
    { TLV_IEEE80211_N, "ieee80211n", 0 },
    { TLV_IEEE80211_AC, "ieee80211ac", 0 },
    { TLV_COUNTRY_CODE, "country_code", 0 },
    { TLV_WMM_ENABLED, "wmm_enabled", 0 },
    { TLV_WPA, "wpa", 0 },
    { TLV_WPA_KEY_MGMT, "wpa_key_mgmt", 0 },
    { TLV_RSN_PAIRWISE, "rsn_pairwise", 0 },
    { TLV_WPA_PASSPHRASE, "wpa_passphrase", 0 },
    { TLV_WPA_PAIRWISE, "wpa_pairwise", 0 },
    { TLV_HT_CAPB, "ht_capab", 0 },
    { TLV_IEEE80211_W, "ieee80211w", 0 },
    { TLV_IEEE80211_H, "ieee80211h", 0 },
    { TLV_VHT_OPER_CHWIDTH, "vht_oper_chwidth", 0 },
    { TLV_VHT_OPER_CENTR_REQ, "vht_oper_centr_freq_seg0_idx", 0 },
    { TLV_EAP_SERVER, "eap_server", 0 },
    { TLV_EAPOL_KEY_INDEX_WORKAROUND, "eapol_key_index_workaround", 0 },
    { TLV_AUTH_SERVER_ADDR, "auth_server_addr", 0 },
    { TLV_AUTH_SERVER_PORT, "auth_server_port", 0 },
    { TLV_AUTH_SERVER_SHARED_SECRET, "auth_server_shared_secret", 0 },
    { TLV_LOGGER_SYSLOG, "logger_syslog", 0 },
    { TLV_LOGGER_SYSLOG_LEVEL, "logger_syslog_level", 0 },
    { TLV_MBO, "mbo", 0 },
    { TLV_MBO_CELL_DATA_CONN_PREF, "mbo_cell_data_conn_pref", 0 },
    { TLV_BSS_TRANSITION, "bss_transition", 0 },
    { TLV_INTERWORKING, "interworking", 0 },
    { TLV_RRM_NEIGHBOR_REPORT, "rrm_neighbor_report", 0 },
    { TLV_RRM_BEACON_REPORT, "rrm_beacon_report", 0 },
    { TLV_COUNTRY3, "country3", 0 },
    { TLV_MBO_CELL_CAPA, "mbo_cell_capa", 0 },
    { TLV_HE_OPER_CHWIDTH, "he_oper_chwidth", 0 },
    { TLV_IEEE80211_AX, "ieee80211ax", 0 },
    { TLV_MBO_ASSOC_DISALLOW, "mbo_assoc_disallow", 0 },
    { TLV_GAS_COMEBACK_DELAY, "gas_comeback_delay", 0 },
    { TLV_SAE_PWE, "sae_pwe", 0 },
    { TLV_OWE_GROUPS, "owe_groups", 0 },
    { TLV_HE_MU_EDCA, "he_mu_edca_qos_info_param_count", 0 },
    { TLV_TRANSITION_DISABLE, "transition_disable", 0 },

    /* wpas, seperate? */
    { TLV_STA_SSID, "ssid", 1 },
    { TLV_KEY_MGMT, "key_mgmt", 0 },
    { TLV_STA_WEP_KEY0, "wep_key0", 0 },
    { TLV_WEP_TX_KEYIDX, "wep_tx_keyidx", 0 },
    { TLV_GROUP, "group", 0 },
    { TLV_PSK, "psk", 1 },
    { TLV_PROTO, "proto", 0 },
    { TLV_STA_IEEE80211_W, "ieee80211w", 0 },
    { TLV_PAIRWISE, "pairwise", 0 },
    { TLV_EAP, "eap", 0 },
    { TLV_PHASE1, "phase1", 1 },
    { TLV_PHASE2, "phase2", 1 },
    { TLV_IDENTITY, "identity", 1 },
    { TLV_PASSWORD, "password", 1 },
    { TLV_CA_CERT, "ca_cert", 1 },
    { TLV_PRIVATE_KEY, "private_key", 1 },
    { TLV_CLIENT_CERT, "client_cert", 1 },
    { TLV_DOMAIN_MATCH, "domain_match", 1 },
    { TLV_DOMAIN_SUFFIX_MATCH, "domain_suffix_match", 1 },
    { TLV_PAC_FILE, "pac_file", 1 },
    { TLV_STA_OWE_GROUP, "owe_group", 0 },
};

struct tlv_to_config_name wpas_global_maps[] = {
    { TLV_STA_SAE_GROUPS, "sae_groups", 0 },
    { TLV_MBO_CELL_CAPA, "mbo_cell_capa", 0 },
    { TLV_SAE_PWE, "sae_pwe", 0 },
};


/* Basic */
static int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int start_loopback_server(struct packet_wrapper *req, struct packet_wrapper *resp);
static int stop_loop_back_server_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_loopback_data_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int assign_static_ip_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int get_mac_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int get_ip_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int reset_device_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
/* AP */
static int stop_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int configure_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int start_ap_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_ap_disconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int set_ap_parameter_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_ap_btm_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int trigger_ap_channel_switch(struct packet_wrapper *req, struct packet_wrapper *resp);
/* STA */
static int stop_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int configure_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int associate_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int start_up_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_sta_disconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_sta_reconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_sta_btm_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int send_sta_anqp_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp);
static int set_sta_parameter_handler(struct packet_wrapper *req, struct packet_wrapper *resp);

#endif // __INDIGO_API_CALLBACK
