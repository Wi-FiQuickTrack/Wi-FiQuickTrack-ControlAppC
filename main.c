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
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "eloop.h"
#include "indigo_api.h"
#include "utils.h"

static void control_receive_message(int sock, void *eloop_ctx, void *sock_ctx);
static int parse_parameters(int argc, char *argv[]);
static void usage();
extern int capture_packet;
extern int debug_packet;

/* Initiate the service port. */
static int control_socket_init(int port) {
    int s;
    struct sockaddr_in addr;

    /* Open UDP socket */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open server socket");
        return -1;
    }

    /* Bind specific port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to bind server socket");
        close(s);
        return -1;
    }

    /* Register to eloop and ready for the socket event */
    if (eloop_register_read_sock(s, control_receive_message, NULL, NULL)) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to initiate ControlAppC");
        return -1;
    }
    return 0;
}

/* Callback function of the Indigo API. */
static void control_receive_message(int sock, void *eloop_ctx, void *sock_ctx) {
    int ret;                          // return code
    int fromlen, len;                 // structure size and received length
    struct sockaddr_storage from;     // source address of the message
    unsigned char buffer[BUFFER_LEN]; // buffer to receive the message
    struct packet_wrapper req, resp;  // packet wrapper for the received message and response
    struct indigo_api *api = NULL;    // used for API search, validation and handler call

    /* Receive request */
    fromlen = sizeof(from);
    len = recvfrom(sock, buffer, BUFFER_LEN, 0, (struct sockaddr *) &from, (socklen_t*)&fromlen);
    if (len < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Server: Failed to receive the packet");
        return ;
    } else {
        indigo_logger(LOG_LEVEL_DEBUG, "Server: Receive the packet");
    }

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
        indigo_logger(LOG_LEVEL_ERROR, "API %s: No registered handler", api->name);
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

    /* TODO: Optional, use timer to handle the execution */
    /* Handle & Response. Call API handle(), assemble packet by response wrapper and send back to source address. */
    if (api->handle && api->handle(&req, &resp) == 0) {
        indigo_logger(LOG_LEVEL_INFO, "API %s: Return execution result", api->name);
        len = assemble_packet(buffer, BUFFER_LEN, &resp);
        sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (const struct sockaddr *) &from, fromlen); 
    } else {
        indigo_logger(LOG_LEVEL_DEBUG, "API %s: No handle function", api->name);
    }

done:
    /* Clean up resource */
    free_packet_wrapper(&req);
    free_packet_wrapper(&resp);
    indigo_logger(LOG_LEVEL_DEBUG, "API %s: Complete", api->name);
}

/* Show the usage */
static void usage() {
    printf("usage:\n");
    printf("app [-h] [-p<port number>] [-i<wireless interface>]\n\n");
    printf("usage:\n");
    printf("  -d = debug received and sent message\n");
    printf("  -i = wireless interface used by the test\n");
    printf("  -p = port number of the application\n\n");
}

/* Parse the commandline parameters */
static int parse_parameters(int argc, char *argv[]) {
    int c;

    while ((c = getopt(argc, argv, "i:hp:dc")) != -1) {
        switch (c) {
        case 'c':
            capture_packet = 1;
            break;
        case 'd':
            debug_packet = 1;
            break;
        case 'h':
            usage();
            return 1;
        case 'i':
            set_wireless_interface(optarg);
            break;
        case 'p':
            set_service_port(atoi(optarg));
            break;
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    /* Initiate the application */
    set_wireless_interface(WIRELESS_INTERFACE_DEFAULT);
    set_hapd_ctrl_path(HAPD_CTRL_PATH_DEFAULT);
    set_hapd_global_ctrl_path(HAPD_GLOBAL_CTRL_PATH_DEFAULT);
    set_hapd_conf_file(HAPD_CONF_FILE_DEFAULT);
    set_wpas_ctrl_path(WPAS_CTRL_PATH_DEFAULT);
    set_wpas_global_ctrl_path(WPAS_GLOBAL_CTRL_PATH_DEFAULT);
    set_wpas_conf_file(WPAS_CONF_FILE_DEFAULT);

    if (parse_parameters(argc, argv)) {
        return 0;
    }

    indigo_logger(LOG_LEVEL_INFO, "Indigo control app running at: %d", get_service_port());
    indigo_logger(LOG_LEVEL_INFO, "Wireless Interface: %s", get_wireless_interface());
    indigo_logger(LOG_LEVEL_INFO, "Hostapd Global Control Interface: %s", get_hapd_global_ctrl_path());
    indigo_logger(LOG_LEVEL_INFO, "Hostapd Control Interface: %s", get_hapd_ctrl_path());
    indigo_logger(LOG_LEVEL_INFO, "WPA Supplicant Control Interface: %s", get_wpas_ctrl_path());

    /* Register the callback */
    register_apis();

    /* Start eloop */
    eloop_init(NULL);

    /* bind the service port and register to eloop */
    if (control_socket_init(get_service_port()) == 0) {
        eloop_run();
    } else {
        indigo_logger(LOG_LEVEL_INFO, "Failed to initiate the UDP socket");
    }

    /* Stop eloop */
    eloop_destroy();
    indigo_logger(LOG_LEVEL_INFO, "ControlAppC stops");

    return 0;
}
