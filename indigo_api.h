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

#ifndef _INDIGO_API_
#define _INDIGO_API_
#include "indigo_packet.h"

/* API */
#define NAME_SIZE     64

struct indigo_tlv {
    unsigned short id;
    char name[NAME_SIZE];
};

struct indigo_api {
    unsigned short type;
    char name[NAME_SIZE];
    int (*verify)(struct packet_wrapper *req, struct packet_wrapper *resp);
    int (*handle)(struct packet_wrapper *req, struct packet_wrapper *resp);
};

/* API definition */
#define API_VERSION                             0x01
#define API_RESERVED_BYTE                       0xff

/* Message type definition */
#define API_CMD_RESPONSE                        0x0000
#define API_CMD_ACK                             0x0001
#define API_AP_START_UP                         0x1000
#define API_AP_STOP                             0x1001
#define API_AP_CONFIGURE                        0x1002
#define API_AP_TRIGGER_CHANSWITCH               0x1003
#define API_AP_SEND_DISCONNECT                  0x1004
#define API_STA_ASSOCIATE                       0x2000
#define API_STA_CONFIGURE                       0x2001
#define API_STA_DISCONNECT                      0x2002
#define API_STA_SEND_DISCONNECT                 0x2003
#define API_GET_IP_ADDR                         0x5000
#define API_GET_MAC_ADDR                        0x5001
#define API_GET_CONTROL_APP_VERSION             0x5002
#define API_INDIGO_START_LOOP_BACK_SERVER       0x5003
#define API_INDIGO_STOP_LOOP_BACK_SERVER        0x5004
#define API_CREATE_NEW_INTERFACE_BRIDGE_NETWORK 0x5005
#define API_ASSIGN_STATIC_IP                    0x5006
#define API_DEVICE_RESET                        0x5007

/* TLV definition */
#define TLV_SSID                                0x0001
#define TLV_CHANNEL                             0x0002
#define TLV_WEP_KEY0                            0x0003
#define TLV_AUTH_ALGORITHM                      0x0004
#define TLV_WEP_DEFAULT_KEY                     0x0005
#define TLV_IEEE80211_D                         0x0006
#define TLV_IEEE80211_N                         0x0007
#define TLV_IEEE80211_AC                        0x0008
#define TLV_COUNTRY_CODE                        0x0009
#define TLV_WMM_ENABLED                         0x000a
#define TLV_WPA                                 0x000b
#define TLV_WPA_KEY_MGMT                        0x000c
#define TLV_RSN_PAIRWISE                        0x000d
#define TLV_WPA_PASSPHRASE                      0x000e
#define TLV_WPA_PAIRWISE                        0x000f
#define TLV_HT_CAPB                             0x0010
#define TLV_IEEE80211_H                         0x0011
#define TLV_IEEE80211_W                         0x0012
#define TLV_VHT_OPER_CHWIDTH                    0x0013
#define TLV_VHT_OPER_CENTR_REQ                  0x0014
#define TLV_IEEE8021_X                          0x0015
#define TLV_EAP_SERVER                          0x0016
#define TLV_AUTH_SERVER_ADDR                    0x0017
#define TLV_AUTH_SERVER_PORT                    0x0018
#define TLV_AUTH_SERVER_SHARED_SECRET           0x0019
#define TLV_INTERFACE_NAME                      0x001a
#define TLV_NEW_INTERFACE_NAME                  0x001b
#define TLV_FREQUENCY                           0x001c
#define TLV_BSS_IDENTIFIER                      0x001d
#define TLV_HW_MODE                             0x001e
#define TLV_VHT_OPER_CENTR_FREQ                 0x001f
#define TLV_EAPOL_KEY_INDEX_WORKAROUND          0x0020
#define TLV_LOGGER_SYSLOG                       0x0021
#define TLV_LOGGER_SYSLOG_LEVEL                 0x0022
#define TLV_IE_OVERRIDE                         0x0023
#define TLV_RECONFIG                            0x0024
#define TLV_SAME_ANONCE                         0x0025
#define TLV_INTERFACE                           0x0026
#define TLV_FRAME_TYPE                          0x0027
#define TLV_ADDRESS                             0x0028
#define TLV_REASON                              0x0029
#define TLV_TEST                                0x002a
#define TLV_VENDOR_ELEMENTS                     0x002b
#define TLV_ASSOCRESP_ELEMENTS                  0x002c
#define TLV_SOURCE_ADDRESS                      0x002d
#define TLV_FRAME_CONTROL                       0x002e
#define TLV_TIMEOUT                             0x002f
#define TLV_EVENT                               0x0030
#define TLV_CLEAR                               0x0031
#define TLV_SAE_COMMIT_OVERRIDE                 0x0032
#define TLV_DISABLE_PMKSA_CACHING               0x0033
#define TLV_SAE_ANTI_CLOGGING_THRESHOLD         0x0034
#define TLV_STA_SSID                            0x0035
#define TLV_KEY_MGMT                            0x0036
#define TLV_STA_WEP_KEY0                        0x0037
#define TLV_WEP_TX_KEYIDX                       0x0038
#define TLV_GROUP                               0x0039
#define TLV_PSK                                 0x003a
#define TLV_PROTO                               0x003b
#define TLV_STA_IEEE80211_W                     0x003c
#define TLV_PAIRWISE                            0x003d
#define TLV_EAP                                 0x003e
#define TLV_PHASE2                              0x003f
#define TLV_IDENTITY                            0x0040
#define TLV_PASSWORD                            0x0041
#define TLV_CA_CERT                             0x0042
#define TLV_PHASE1                              0x0043
#define TLV_CLIENT_CERT                         0x0044
#define TLV_PRIVATE_KEY                         0x0045
#define TLV_STA_IE_OVERRIDE                     0x0046
#define TLV_STA_MAC_ADDRESS                     0x0047
#define TLV_STA_CLEAR                           0x0048
#define TLV_STA_TIMEOUT                         0x0049
#define TLV_STA_EVENT                           0x004a
#define TLV_STA_LOCALLY_GENERATED               0x004b
#define TLV_FREQ                                0x004c
#define TLV_FORCE_SCAN                          0x004d
#define TLV_PASSIVE                             0x004e
#define TLV_STA_COMMIT_OVERRIDE                 0x004f
#define TLV_AP_MAC_ADDRESS                      0x0050
#define TLV_SAE_RECONNECT                       0x0051
#define TLV_STA_POWER_SAVE                      0x0052
#define TLV_TOOL_IP_ADDRESS                     0x0053
#define TLV_TOOL_UDP_PORT                       0x0054
#define TLV_STATIC_IP                           0x0055
#define TLV_DEVICE_ROLE                         0x0056
#define TLV_DEBUG_LEVEL                         0x0057
#define TLV_DUT_IP_ADDRESS                      0x0058
#define TLV_HOSTAPD_FILE_NAME                   0x0059
#define TLV_DUT_TYPE                            0x005a
#define TLV_CONCURRENT_HOSTAPD_FILE             0x005b
#define TLV_ROLE                                0x005c
#define TLV_BAND                                0x005d
#define TLV_BSSID                               0x005e
#define TLV_ARP_TRANSMISSION_RATE               0x005f
#define TLV_ARP_TARGET_IP                       0x0060
#define TLV_ARP_TARGET_MAC                      0x0061
#define TLV_ARP_FRAME_COUNT                     0x0062
#define TLV_CHANGE_ANONCE                       0x0063
#define TLV_USE_PLAIN_TEXT                      0x0064
#define TLV_REPEAT_M3_FRAMES                    0x0065
#define TLV_M3_FRAME_REPEAT_RATE                0x0066
#define TLV_PACKET_COUNT                        0x0067
#define TLV_SEND_M1_FRAMES                      0x0068
#define TLV_UDP_PACKET_RATE                     0x0069
#define TLV_PHYMODE                             0x006a
#define TLV_CHANNEL_WIDTH                       0x006b
#define TLV_WMM_MODE                            0x006c
#define TLV_PAC_FILE                            0x006d
#define TLV_STA_SAE_GROUPS                      0x006e
#define TLV_BROADCAST_ADDR                      0x006f
#define TLV_START_IMMEDIATE_M3                  0x0070
#define TLV_SAE_GROUPS                          0x0071
#define TLV_IEEE80211_AX                        0x0072
#define TLV_HE_OPER_CHWIDTH                     0x0073
#define TLV_HE_OPER_CENTR_FREQ                  0x0074
#define TLV_MBO                                 0x0075
#define TLV_MBO_CELL_DATA_CONN_PREF             0x0076
#define TLV_BSS_TRANSITION                      0x0077
#define TLV_INTERWORKING                        0x0078
#define TLV_RRM_NEIGHBOR_REPORT                 0x0079
#define TLV_RRM_BEACON_REPORT                   0x007a
#define TLV_COUNTRY3                            0x007b
#define TLV_MBO_CELL_CAPA                       0x007c
#define TLV_MESSAGE                             0xa000
#define TLV_STATUS                              0xa001
#define TLV_DUT_WLAN_IP_ADDR                    0xa002
#define TLV_DUT_MAC_ADDR                        0xa003
#define TLV_CONTROL_APP_VERSION                 0xa004

struct indigo_api* get_api_by_id(int id);
struct indigo_tlv* get_tlv_by_id(int id);
char* get_api_type_by_id(int id);

typedef int (*api_callback_func)(struct packet_wrapper *req, struct packet_wrapper *resp);
void register_api(int id, api_callback_func verify, api_callback_func handle);

void fill_wrapper_ack(struct packet_wrapper *wrapper, int seq, int status, char *reason);

/* Solution Vendor */
void register_apis();
#endif // __INDIGO_API_