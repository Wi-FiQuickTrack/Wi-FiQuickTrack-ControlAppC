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
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "indigo_api.h"
#include "vendor_specific.h"
#include "utils.h"
#include "wpa_ctrl.h"
#include "indigo_api_callback.h"

extern struct sockaddr_in *tool_addr;

void register_apis() {
    /* Basic */
    register_api(API_GET_CONTROL_APP_VERSION, NULL, get_control_app_handler);
    register_api(API_SNIFFER_START, NULL, sniffer_start_handler);
    register_api(API_SNIFFER_STOP, NULL, sniffer_stop_handler);
    register_api(API_SNIFFER_UPLOAD_FILE, NULL, sniffer_upload_file_handler);
    register_api(API_SNIFFER_FILTER, NULL, sniffer_filter_handler);
}

static int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char buffer[S_BUFFER_LEN];
#ifdef _VERSION_
    snprintf(buffer, sizeof(buffer), "%s", _VERSION_);
#else
    snprintf(buffer, sizeof(buffer), "%s", TLV_VALUE_APP_VERSION);
#endif
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_OK), TLV_VALUE_OK);
    fill_wrapper_tlv_bytes(resp, TLV_TEST_SNIFFER_APP_VERSION, 
        strlen(buffer), buffer);
    return 0;
}

static int sniffer_start_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[S_BUFFER_LEN];
    char channel[8];
    char file_name[32];
    struct tlv_hdr *tlv = NULL;

    memset(channel, 0, sizeof(channel));
    tlv = find_wrapper_tlv_by_id(req, TLV_CHANNEL);
    if (tlv) {
        snprintf(buffer, sizeof(buffer), "ifconfig mon0 up");
        system(buffer);
        sleep(1);
        memcpy(channel, tlv->value, tlv->len);
        snprintf(buffer, sizeof(buffer), "iw dev mon0 set channel %s 80MHz", channel);
        system(buffer);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CHANNEL is missing");
        goto done;
    }

    memset(file_name, 0, sizeof(file_name));
    tlv = find_wrapper_tlv_by_id(req, TLV_CAPTURE_FILE);
    if (tlv) {
        memcpy(file_name, tlv->value, tlv->len);
        unlink(file_name);
        snprintf(buffer, sizeof(buffer), "tcpdump -i mon0 -w %s &", file_name);
        system(buffer);
        sleep(3);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CAPTURE_FILE is missing");
        goto done;
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int sniffer_stop_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[S_BUFFER_LEN];

    snprintf(buffer, sizeof(buffer), "killall tcpdump");
    if (system(buffer) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to shutdown tcpdump\n");
        goto done;
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int sniffer_filter_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[BUFFER_LEN];
    char filter[TLV_VALUE_SIZE];
    char infile_name[TLV_VALUE_SIZE];
    char outfile_name[TLV_VALUE_SIZE];
    struct tlv_hdr *tlv = NULL;

    tlv = find_wrapper_tlv_by_id(req, TLV_CAPTURE_FILTER);
    if (tlv) {
        memset(filter, 0, sizeof(filter));
        memcpy(filter, tlv->value, tlv->len);
   
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CAPTURE_FILTER is missing");
        goto done;
    }

    tlv = find_wrapper_tlv_by_id(req, TLV_CAPTURE_INFILE);
    if (tlv) {
        memset(infile_name, 0, sizeof(infile_name));
        memcpy(infile_name, tlv->value, tlv->len);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CAPTURE_INFILE is missing");
        goto done;
    }

    tlv = find_wrapper_tlv_by_id(req, TLV_CAPTURE_OUTFILE);
    if (tlv) {
        memset(outfile_name, 0, sizeof(outfile_name));
        memcpy(outfile_name, tlv->value, tlv->len);

        snprintf(buffer, sizeof(buffer), "tshark -r %s -Y '%s' -w %s", infile_name, filter, outfile_name);
        indigo_logger(LOG_LEVEL_INFO, "Run: %s", buffer);
        system(buffer);

        if (!file_exists(outfile_name)) {
            indigo_logger(LOG_LEVEL_ERROR, "CAPTURE_OUTFILE file %s does not exist", outfile_name);
            goto done;
        }

    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CAPTURE_OUTFILE is missing");
        goto done;
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int sniffer_upload_file_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[BUFFER_LEN];
    char file_name[TLV_VALUE_SIZE];
    struct tlv_hdr *tlv = NULL;

    memset(file_name, 0, sizeof(file_name));
    tlv = find_wrapper_tlv_by_id(req, TLV_CAPTURE_FILE);
    if (tlv) {
        memcpy(file_name, tlv->value, tlv->len);

        if (!file_exists(file_name)) {
            indigo_logger(LOG_LEVEL_ERROR, "file %s does not exist", file_name);
            goto done;
        }

        if (tool_addr != NULL) {
            snprintf(buffer, sizeof(buffer), "curl -v -F TestArtifacts=@%s http://%s:%d%s", file_name, inet_ntoa(tool_addr->sin_addr), TOOL_POST_PORT, ARTIFACTS_UPLOAD_API);
            indigo_logger(LOG_LEVEL_INFO, "Run: %s", buffer);
            system(buffer);
        }

    } else {
        indigo_logger(LOG_LEVEL_ERROR, "TLV CAPTURE_FILE is missing");
        goto done;
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}