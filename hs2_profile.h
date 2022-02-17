
/* Copyright (c) 2021 Wi-Fi Alliance                                                */

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

#ifndef _HS2_PROFILE
#define _HS2_PROFILE

#define ARRAY_SIZE(x) ((sizeof x) / (sizeof *x))

struct tlv_to_profile {
    unsigned short tlv_id;
    const char **profile;
    int size;
};

const char * nai_realm[] = {
    "",
    "nai_realm=0,mail.example.com,21[2:4][5:7]\nnai_realm=0,cisco.com,21[2:4][5:7]\nnai_realm=0,wi-fi.org,13[5:6],21[2:4][5:7]\nnai_realm=0,example.com,13[5:6]\n",
    "nai_realm=0,wi-fi.org,21[2:4][5:7]\n",
    "nai_realm=0,cisco.com,21[2:4][5:7]\nnai_realm=0,wi-fi.org,13[5:6],21[2:4][5:7]\nnai_realm=0,example.com,13[5:6]\n",
    "nai_realm=0,mail.example.com,13[5:6],21[2:4][5:7]\n",
    "nai_realm=0,wi-fi.org,21[2:4][5:7]\nnai_realm=0,ruckuswireless.com,21[2:4][5:7]\n",
    "nai_realm=0,wi-fi.org,21[2:4][5:7]\nnai_realm=0,mail.example.com,21[2:4][5:7]\n",
    "nai_realm=0,wi-fi.org,13[5:6],21[2:4][5:7]\n",
};

const char * oper_friendly_name[] = {
    "",
    "hs20_oper_friendly_name=eng:Wi-Fi Alliance\nhs20_oper_friendly_name=chi:Wi-Fi联盟\n",
};

const char * venue_name[] = {
    "",
    "venue_name=eng:Wi-Fi Alliance 3408 Garrett Drive Santa Clara, CA 950514, USA\nvenue_name=chi:Wi-Fi聯盟實驗室 三四零八 加洛路 聖克拉拉, 加利福尼亞 950514, 美國\n",
    "",
    "",
};

const char * network_auth_type[] = {
    "",
    "network_auth_type=00https://tandc-server.wi-fi.org/\n",
    "network_auth_type=01\n",
};

const char * ipaddr_type_avail[] = {
    "",
    "ipaddr_type_availability=0c\n",
};

const char * hs20_wan_metrics[] = {
    "",
    "hs20_wan_metrics=01:2500:384:0:0:10\n",
    "",
    "hs20_wan_metrics=01:2000:1000:20:20:10\n",
    "hs20_wan_metrics=01:8000:1000:20:20:10\n",
    "",
};

const char * hs20_conn_capab[] = {
    "",
    "hs20_conn_capab=6:20:1\nhs20_conn_capab=6:80:1\nhs20_conn_capab=6:443:1\nhs20_conn_capab=50:0:1\n",
    "",
    "",
    "",
    "",
};

const char * operating_class_indication[] = {
    "",
    "hs20_operating_class=51\n",
    "hs20_operating_class=73\n",
    "hs20_operating_class=5173\n",
};

const char * osu_providers_list[] = {
    "",
    "osu_server_uri=https://osu-server.r2-testbed.wi-fi.org/\nosu_friendly_name=eng:SP Red Test Only\nosu_friendly_name=kor:SP 빨강 테스트 전용\nosu_method_list=1\nosu_service_desc=eng:Free service for test purpose\nosu_service_desc=kor:테스트 목적으로 무료 서비스\n",
    "",
    "",
    "",
    "",
};

const char * osu_providers_nai_list[] = {
    "",
    "",
    "",
    "",
    "",
};

const char * bss_load[] = {
    "",
    "",
    "",
    "",
};

const char * venue_url[] = {
    "",
    "venue_url=1:https://venue-server.r2m-testbed.wi-fi.org/floorplans/index.html\nvenue_url=2:https://venue-server.r2m-testbed.wi-fi.org/directory/index.html\n",
    "",
};

const char * operator_icon_metadata[] = {
    "",
    "operator_icon=icon_red_eng\n",
};

// <Icon Width>:<Icon Height>:<Language code>:<Icon Type>:<Name>:<file path>
const char * hs20_icon[] = {
    "hs20_icon=160:76:eng:image/png:icon_red_eng:/overlay/icon_red_eng.png\n",
};

struct tlv_to_profile hs2_profile[] = {
    { TLV_VENUE_NAME, venue_name, ARRAY_SIZE(venue_name) },
    { TLV_NAI_REALM, nai_realm, ARRAY_SIZE(nai_realm) },
    { TLV_HS20_OPERATOR_FRIENDLY_NAME, oper_friendly_name, ARRAY_SIZE(oper_friendly_name) },
    { TLV_NETWORK_AUTH_TYPE, network_auth_type, ARRAY_SIZE(network_auth_type) },
    { TLV_IPADDR_TYPE_AVAILABILITY, ipaddr_type_avail, ARRAY_SIZE(ipaddr_type_avail) },
    { TLV_HS20_WAN_METRICS, hs20_wan_metrics, ARRAY_SIZE(hs20_wan_metrics) },
    { TLV_HS20_CONN_CAPABILITY, hs20_conn_capab, ARRAY_SIZE(hs20_conn_capab) },
    { TLV_OSU_PROVIDERS_LIST, osu_providers_list, ARRAY_SIZE(osu_providers_list) },
    { TLV_OSU_PROVIDERS_NAI_LIST, osu_providers_nai_list, ARRAY_SIZE(osu_providers_nai_list) },
    { TLV_VENUE_URL, venue_url, ARRAY_SIZE(venue_url) },
    { TLV_BSSLOAD_ENABLE, bss_load, ARRAY_SIZE(bss_load) },
    { TLV_OPERATOR_ICON_METADATA, operator_icon_metadata, ARRAY_SIZE(operator_icon_metadata) },
    { TLV_HS20_OPERATING_CLASS_INDICATION, operating_class_indication, ARRAY_SIZE(operating_class_indication) },
};

struct tlv_to_profile* find_tlv_hs2_profile(int tlv_id) {
    int i;
    for (i = 0; i < ARRAY_SIZE(hs2_profile); i++) {
        if (tlv_id == hs2_profile[i].tlv_id) {
            return &hs2_profile[i];
        }
    }
    return NULL;
}

void attach_hs20_icons(char * buffer) {
    int i;
    for (i = 0; i < ARRAY_SIZE(hs20_icon); i++) {
        strcat(buffer, hs20_icon[i]);
    }
    return;
}

#endif // _HS2_PROFILE