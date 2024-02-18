/* Copyright (c) 2023 Wi-Fi Alliance                                                */

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
#include <netinet/in.h>
#include <errno.h>

#include "vendor_specific.h"
#include "eloop.h"
#include "indigo_api.h"
#include "utils.h"


struct sockaddr_in *tool_addr; // For HTTP Post
/* Callback function of the QuickTrack API. */
static void control_receive_message(int sock, void *eloop_ctx, void *sock_ctx) {
    int ret;                          // return code
    int fromlen, len;                 // structure size and received length
    struct sockaddr_storage from;     // source address of the message
    char buffer[BUFFER_LEN]; // buffer to receive the message
    struct packet_wrapper req, resp;  // packet wrapper for the received message and response
    struct indigo_api *api = NULL;    // used for API search, validation and handler call

    (void) eloop_ctx;
    (void) sock_ctx;

    /* Receive request */
    fromlen = sizeof(from);
    len = recvfrom(sock, buffer, BUFFER_LEN, 0, (struct sockaddr *) &from, (socklen_t*)&fromlen);
    if (len < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Server: Failed to receive the packet");
        return ;
    } else {
        indigo_logger(LOG_LEVEL_DEBUG, "Server: Receive the packet");
    }
    tool_addr = (struct sockaddr_in *)&from;

    /* Parse request to HDR and TLV. Response NACK if parser fails. Otherwises, ACK. */
    memset(&req, 0, sizeof(struct packet_wrapper));
    memset(&resp, 0, sizeof(struct packet_wrapper));
    ret = parse_packet(&req, buffer, len);
    if (ret == 0) {
        indigo_logger(LOG_LEVEL_DEBUG, "Server: Parsed packet successfully");
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Server: Failed to parse the packet");
        fill_wrapper_ack(&resp, req.hdr.seq, 0x31, "Unable to parse the packet");
        len = assemble_packet(buffer, BUFFER_LEN, &resp);

        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen);
        goto done;
    }

    /* Find API by ID. If API is not supported, assemble NACK. */
    api = get_api_by_id(req.hdr.type);
    if (api) {
        indigo_logger(LOG_LEVEL_DEBUG, "API %s: Found handler", api->name);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "API Unknown (0x%04x): No registered handler", req.hdr.type);
        fill_wrapper_ack(&resp, req.hdr.seq, 0x31, "Unable to find the API handler");
        len = assemble_packet(buffer, BUFFER_LEN, &resp);
        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen);
        goto done;
    }

    /* Verify. Optional. If validation is failed, then return NACK. */
    if (api->verify == NULL || (api->verify && api->verify(&req, &resp) == 0)) {
        indigo_logger(LOG_LEVEL_INFO, "API %s: Return ACK", api->name);
        fill_wrapper_ack(&resp, req.hdr.seq, 0x30, "ACK: Command received");
        len = assemble_packet(buffer, BUFFER_LEN, &resp);
        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen);
        free_packet_wrapper(&resp);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "API %s: Failed to verify and return NACK", api->name);
        fill_wrapper_ack(&resp, req.hdr.seq, 1, "Unable to find the API handler");
        len = assemble_packet(buffer, BUFFER_LEN, &resp);
        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen);
        goto done;
    }

    /* Optional, use timer to handle the execution */
    /* Handle & Response. Call API handle(), assemble packet by response wrapper and send back to source address. */
    if (api->handle && api->handle(&req, &resp) == 0) {
        indigo_logger(LOG_LEVEL_INFO, "API %s: Return execution result", api->name);
        len = assemble_packet(buffer, BUFFER_LEN, &resp);
        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen);
    } else {
        indigo_logger(LOG_LEVEL_DEBUG, "API %s (0x%04x): No handle function", api ? api->name : "Unknown", req.hdr.type);
    }

done:
    /* Clean up resource */
    free_packet_wrapper(&req);
    free_packet_wrapper(&resp);
    indigo_logger(LOG_LEVEL_DEBUG, "API %s: Complete", api ? api->name : "Unknown");
}

/* Initiate the service port. */
int control_socket_init(int port) {
    int s = -1;
    char cmd[S_BUFFER_LEN];
    struct sockaddr_in addr;

    /* Open UDP socket */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open server socket: %s", strerror(errno));
        return -1;
    }

    /* Bind specific port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to bind server socket: %s", strerror(errno));
        if (errno == EADDRINUSE) {
            sprintf(cmd, "netstat -lunatp | grep %d", port);
            system(cmd);
        }
        close(s);
        return -1;
    }

    /* Register to eloop and ready for the socket event */
    if (qt_eloop_register_read_sock(s, control_receive_message, NULL, NULL)) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to initiate ControlAppC");
        close(s);
        return -1;
    }
    return s;
}
