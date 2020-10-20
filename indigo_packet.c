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
#include <stdlib.h>

#include "indigo_api.h"
#include "utils.h"

int debug_packet = 0;
int debug_assemble_packet = 0;

int parse_packet(struct packet_wrapper *req, char *packet, int packet_len) {
    int parser = 0, ret, i;
    struct indigo_api *api;
    struct indigo_tlv *tlv;

    ret = parse_message_hdr(&req->hdr, packet, packet_len);
    if (ret > 0) {
        if (debug_packet) {
            print_message_hdr(&req->hdr);
        }
        parser += ret;
    } else {
        return -1;
    }

    while (packet_len - parser > 0) {
        req->tlv[req->tlv_num] = (struct tlv_hdr *)malloc(sizeof(struct tlv_hdr));
        memset(req->tlv[req->tlv_num], 0, sizeof(struct tlv_hdr));

        ret = parse_tlv(req->tlv[req->tlv_num], packet + parser, packet_len - parser);
        if (ret > 0) {
            if (debug_packet) {
                print_tlv(req->tlv[req->tlv_num]);
            }

            req->tlv_num++;
            parser += ret;
        } else {
            break;
        }
    }
    
    api = get_api_by_id(req->hdr.type);
    if (api) {
        indigo_logger(LOG_LEVEL_INFO, "API: 0x%04x (%s)", api->type, api->name);
    } else {
        indigo_logger(LOG_LEVEL_WARNING, "API: 0x%04x Unknown", req->hdr.type);
        return -1;
    }

    for (i = 0; i < req->tlv_num; i++) {
        tlv = get_tlv_by_id(req->tlv[i]->id);
        if (tlv) {
            indigo_logger(LOG_LEVEL_INFO, "    TLV: 0x%04x (%s)", tlv->id, tlv->name);
        } else {
            indigo_logger(LOG_LEVEL_WARNING, "    TLV: 0x%04x Unknown", req->tlv[i]->id);
            return -1;
        }
    }
    return 0;
}

struct tlv_hdr *find_wrapper_tlv_by_id(struct packet_wrapper *wrapper, int id) {
    int i;

    for (i = 0; i < TLV_NUM; i++) {
        if (wrapper->tlv[i]) {
            if (wrapper->tlv[i]->id == id) {
                return wrapper->tlv[i];
            }
        }
    }

    return NULL;
}

int free_packet_wrapper(struct packet_wrapper *wrapper) {
    int i;

    for (i = 0; i < TLV_NUM; i++) {
        if (wrapper->tlv[i]) {
            free(wrapper->tlv[i]);
        }
    }
    memset(wrapper, 0, sizeof(struct packet_wrapper));

    return 0;
}

int parse_message_hdr(struct message_hdr *hdr, char *message, int message_len) {
    if (message_len < sizeof(struct message_hdr)) {
        return -1;
    }

    hdr->version = message[0];
    hdr->type = ((message[1] & 0x00ff) << 8) | (message[2] & 0x00ff);
    hdr->seq = ((message[3] & 0x00ff) << 8) | (message[4] & 0x00ff);
    hdr->reserved = message[5];
    hdr->reserved2 = message[6];

    return sizeof(struct message_hdr);
}

int gen_message_hdr(char *message, int message_len, struct message_hdr *hdr) {
    int len = 0;

    if (message_len < sizeof(struct message_hdr)) {
        return -1;
    }

    message[len++] = hdr->version;
    message[len++] = (char) (hdr->type >> 8);
    message[len++] = (char) (hdr->type & 0x00ff);
    message[len++] = (char) (hdr->seq >> 8);
    message[len++] = (char) (hdr->seq & 0x00ff);
    message[len++] = hdr->reserved;
    message[len++] = hdr->reserved2;
    
    return sizeof(struct message_hdr);
}

void print_message_hdr(struct message_hdr *hdr) {
    indigo_logger(LOG_LEVEL_INFO, "Version: %d", hdr->version);
    indigo_logger(LOG_LEVEL_INFO, "Type: 0x%04x (%s)", hdr->type, get_api_type_by_id(hdr->type));
    indigo_logger(LOG_LEVEL_INFO, "Seqence: 0x%04x", hdr->seq);
    indigo_logger(LOG_LEVEL_INFO, "Reserved: 0x%02x", hdr->reserved);
    indigo_logger(LOG_LEVEL_INFO, "Reserved2: 0x%02x", hdr->reserved2);
}

int print_hex(char *message, int message_len) {
    int i;
    for(i = 0; i < message_len; i++)  {
        printf("0x%02x ", (unsigned char)message[i]);
    }
    printf("\n\n");
    return 0;
}

int parse_tlv(struct tlv_hdr *tlv, char *packet, int packet_len) {
    if (packet_len < 3) {
        return -1;
    }

    tlv->id = ((packet[0] & 0x00ff) << 8) | (packet[1] & 0x00ff);
    tlv->len = packet[2];
    tlv->value = (char*)malloc(sizeof(char) * tlv->len);
    memcpy(tlv->value, &packet[3], tlv->len);

    return tlv->len+3;
}

int gen_tlv(char *packet, int packet_size, struct tlv_hdr *t) {
    int len = 0;

    if (packet_size < t->len + 3) {
        return -1;
    }

    packet[len++] = (char) (t->id >> 8);
    packet[len++] = (char) (t->id & 0x00ff);
    packet[len++] = t->len;
    memcpy(&packet[len], t->value, t->len);
    len += t->len;
    
    return len;
}

void print_tlv(struct tlv_hdr *t) {
    int i;
    char buffer[256];
    struct indigo_tlv *tlv = get_tlv_by_id(t->id);

    indigo_logger(LOG_LEVEL_INFO, "ID: 0x%04x (%s)", t->id, tlv == NULL ? "Unknown" : tlv->name);
    indigo_logger(LOG_LEVEL_INFO, "Length: %d", t->len);

    memset(buffer, 0, sizeof(buffer));
    if (t->len > 0) {
        sprintf(buffer, "Value: ");
    }
    for (i = 0; i < t->len; i++) {
        sprintf(buffer, "%s0x%02x ", buffer, t->value[i]);
    }
    indigo_logger(LOG_LEVEL_INFO, buffer);
}

int assemble_packet(char *packet, int packet_size, struct packet_wrapper *wrapper) {
    int packet_len = 0, i, ret;

    ret = gen_message_hdr(packet, packet_size, &wrapper->hdr);
    packet_len += ret;

    for (i = 0; i < wrapper->tlv_num; i++) {
        ret = gen_tlv(packet + packet_len, packet_size - packet_len, wrapper->tlv[i]);
        if (ret) {
            packet_len += ret;
        } else {
            break;
        }
    }

    if (debug_assemble_packet)
        print_hex(packet, packet_len);

    return packet_len;
}
