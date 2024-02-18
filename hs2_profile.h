
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

#define ADVICE_OF_CHARGE_1 \
"bc01000000d200454e475553443c3f786d6c2076657273696f6e3d22312e30222065" \
"6e636f64696e673d225554462d38223f3e3c506c616e20786d6c6e733d22687474703a2f2f77" \
"77772e77692d66692e6f72672f73706563696669636174696f6e732f686f7473706f7432646f" \
"74302f76312e302f616f637069223e3c4465736372697074696f6e3e57692d46692061636365" \
"737320666f72203120686f75722c207768696c6520796f752077616974206174207468652067" \
"6174652c2024302e39393c2f4465736372697074696f6e3e3c2f506c616e3ee3004652414341" \
"443c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f" \
"3e3c506c616e20786d6c6e733d22687474703a2f2f7777772e77692d66692e6f72672f737065" \
"63696669636174696f6e732f686f7473706f7432646f74302f76312e302f616f637069223e3c" \
"4465736372697074696f6e3e416363c3a8732057692d46692070656e64616e74203120686575" \
"72652c2070656e64616e742071756520766f757320617474656e64657a20c3a0206c6120706f" \
"7274652c20302c393920243c2f4465736372697074696f6e3e3c2f506c616e3ea101010000c7" \
"00454e475553443c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d2255" \
"54462d38223f3e3c506c616e20786d6c6e733d22687474703a2f2f7777772e77692d66692e6f" \
"72672f73706563696669636174696f6e732f686f7473706f7432646f74302f76312e302f616f" \
"637069223e3c4465736372697074696f6e3e446f776e6c6f616420766964656f7320666f7220" \
"796f757220666c696768742c2024322e393920666f7220313047423c2f446573637269707469" \
"6f6e3e3c2f506c616e3ed3004652414341443c3f786d6c2076657273696f6e3d22312e302220" \
"656e636f64696e673d225554462d38223f3e3c506c616e20786d6c6e733d22687474703a2f2f" \
"7777772e77692d66692e6f72672f73706563696669636174696f6e732f686f7473706f743264" \
"6f74302f76312e302f616f637069223e3c4465736372697074696f6e3e54c3a96cc3a9636861" \
"7267657a2064657320766964c3a96f7320706f757220766f74726520766f6c2c20322c393920" \
"2420706f757220313020476f3c2f4465736372697074696f6e3e3c2f506c616e3ee40003002b" \
"736572766963652d70726f76696465722e636f6d3b66656465726174696f6e2e6578616d706c" \
"652e636f6db400454e475553443c3f786d6c2076657273696f6e3d22312e302220656e636f64" \
"696e673d225554462d38223f3e3c506c616e20786d6c6e733d22687474703a2f2f7777772e77" \
"692d66692e6f72672f73706563696669636174696f6e732f686f7473706f7432646f74302f76" \
"312e302f616f637069223e3c4465736372697074696f6e3e46726565207769746820796f7572" \
"20737562736372697074696f6e213c2f4465736372697074696f6e3e3c2f506c616e3e"

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
    "network_auth_type=00https://tandc-server.wi-fi.org\n",
    "network_auth_type=01\n",
};

const char * ipaddr_type_avail[] = {
    "",
    "ipaddr_type_availability=0c\n",
};

const char * hs20_wan_metrics[] = {
    "",
    "hs20_wan_metrics=01:2500:384:0:0:10\n",
    "hs20_wan_metrics=01:1500:384:20:20:10\n",
    "hs20_wan_metrics=01:2000:1000:20:20:10\n",
    "hs20_wan_metrics=01:8000:1000:20:20:10\n",
    "hs20_wan_metrics=01:9000:5000:20:20:10\n",
};

const char * hs20_conn_capab[] = {
    "",
    "hs20_conn_capab=6:20:1\nhs20_conn_capab=6:80:1\nhs20_conn_capab=6:443:1\nhs20_conn_capab=17:500:1\nhs20_conn_capab=50:0:1\n",
    "",
    "hs20_conn_capab=6:80:1\nhs20_conn_capab=6:443:1\n",
    "hs20_conn_capab=6:80:1\nhs20_conn_capab=6:443:1\nhs20_conn_capab=6:5060:1\nhs20_conn_capab=17:5060:1\n",
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
    "osu_ssid=\"OSU\"\nosu_server_uri=https://osu-server.r2-testbed.wi-fi.org/\nosu_friendly_name=eng:SP Red Test Only\nosu_friendly_name=kor:SP 빨강 테스트 전용\nosu_method_list=1\nosu_icon=icon_red_eng.png\nosu_icon=icon_red_zxx.png\nosu_service_desc=eng:Free service for test purpose\nosu_service_desc=kor:테스트 목적으로 무료 서비스\n",
    "",
    "",
    "",
    "",
};

const char * osu_providers_nai_list[] = {
    "",
    "osu_nai2=anonymous@hotspot.net\n",
    "",
    "",
    "",
};

const char * bss_load[] = {
    "",
    "bss_load_test=1:50:65535\n",
    "bss_load_test=1:200:65535\n",
    "bss_load_test=1:75:65535\n",
};

const char * venue_url[] = {
    "",
    "venue_url=1:https://venue-server.r2m-testbed.wi-fi.org/floorplans/index.html\nvenue_url=1:https://venue-server.r2m-testbed.wi-fi.org/directory/index.html\n",
    "",
};

const char * operator_icon_metadata[] = {
    "",
    "operator_icon=icon_red_eng.png\n",
};

const char * advice_of_charge[] = {
    "",
    "anqp_elem=278:" ADVICE_OF_CHARGE_1 "\n",
};

// <Icon Width>:<Icon Height>:<Language code>:<Icon Type>:<Name>:<file path>
const char * hs20_icon[] = {
    "hs20_icon=160:76:eng:image/png:icon_red_eng.png:/overlay/passpoint/icon_red_eng.png\n",
    "hs20_icon=128:61:zxx:image/png:icon_red_zxx.png:/overlay/passpoint/icon_red_zxx.png\n",
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
    { TLV_ADVICE_OF_CHARGE, advice_of_charge, ARRAY_SIZE(advice_of_charge) },
};

struct tlv_to_profile* find_tlv_hs2_profile(int tlv_id) {
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(hs2_profile); i++) {
        if (tlv_id == hs2_profile[i].tlv_id) {
            return &hs2_profile[i];
        }
    }
    return NULL;
}

void attach_hs20_icons(char * buffer) {
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(hs20_icon); i++) {
        strcat(buffer, hs20_icon[i]);
    }
    return;
}

#endif // _HS2_PROFILE