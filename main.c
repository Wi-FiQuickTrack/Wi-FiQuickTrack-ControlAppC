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
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>

#include "vendor_specific.h"
#include "eloop.h"
#include "indigo_api.h"
#include "utils.h"


/* Internal functions */
int control_socket_init(int port);
static int parse_parameters(int argc, char *argv[]);
static void usage();

/* External variables */
extern int capture_packet; /* debug. Write the received packets to files */
extern int debug_packet;   /* used by the packet hexstring print */

/* Show the usage */
static void usage() {
    printf("usage:\n");
    printf("app [-h] [-p<port number>] [-i<wireless interface>|-i<band>:<interface>[,<band>:<interface>]] [-a<hostapd path>] [-s<wpa_supplicant path>]\n\n");
    printf("usage:\n");
    printf("  -a = specify hostapd path\n");
    printf("  -b = specify bridge name for wireless interfaces\n");
    printf("  -d = debug received and sent message\n");
    printf("  -i = specify the interface. E.g., -i wlan0. Or, <band>:<interface>.\n       band can be 2 for 2.4GHz, 5 for 5GHz and 6 for 6GHz. E.g., -i 2:wlan0,2:wlan1,5:wlan32,5:wlan33\n");
    printf("  -p = port number of the application\n");
    printf("  -s = specify wpa_supplicant path\n\n");
}

/* Show the welcome message with role and version */
static void print_welcome() {
#ifdef _DUT_
    printf("Welcome to use QuickTrack Control App DUT version");
#else
    printf("Welcome to use Quicktrack Control App Platform version");
#endif

#ifdef _VERSION_
    printf(" %s.\n", _VERSION_);
#else
    printf(".\n");
#endif
}

/* Parse the commandline parameters */
static int parse_parameters(int argc, char *argv[]) {
    int c, ifs_configured = 0, bridge_configured = 0;
    char buf[256];

#ifdef _VERSION_
    while ((c = getopt(argc, argv, "a:b:s:i:hp:dcv")) != -1) {
#else
    while ((c = getopt(argc, argv, "a:b:s:i:hp:dc")) != -1) {
#endif
        switch (c) {
        case 'a':
            set_hapd_full_exec_path(optarg);
            break;
        case 'b':
            set_wlans_bridge(optarg);
            bridge_configured = 1;
            break;
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
            if (set_wireless_interface(optarg) == 0) {
                ifs_configured = 1;
            }
            break;
        case 'p':
            set_service_port(atoi(optarg));
            break;
        case 's':
            set_wpas_full_exec_path(optarg);
            break;
#ifdef _VERSION_
        case 'v':
            return 1;
#endif
        }
    }

    if (optind < argc) {
        printf("\nInvalid option %s\n", argv[optind]);
        usage();
        return 1;
    }

    if (ifs_configured == 0) {
#ifdef DEFAULT_APP_INTERFACES_PARAMS
#ifdef _OPENWRT_
        if (detect_third_radio())
            snprintf(buf, sizeof(buf), "%s", DEFAULT_APP_6E_INTERFACES_PARAMS);
        else
#endif
            snprintf(buf, sizeof(buf), "%s", DEFAULT_APP_INTERFACES_PARAMS);
        printf("\nUse default interface parameters %s.\n", buf);
        set_wireless_interface(buf);
#else
        usage();
        printf("\nWe need to specify the interfaces with -i.\n");
        return 1;
#endif
    }

    if (bridge_configured == 0) {
        set_wlans_bridge(BRIDGE_WLANS);
    }

    return 0;
}

static void handle_term(int sig, void *eloop_ctx, void *signal_ctx) {
    indigo_logger(LOG_LEVEL_INFO, "Signal %d received - terminating\n", sig);
    (void) eloop_ctx;
    (void) signal_ctx;
    qt_eloop_terminate();
    vendor_deinit();
}

int main(int argc, char* argv[]) {
    int service_socket = -1;

    /* Welcome message */
    print_welcome();

    /* Initiate the application */
    set_wireless_interface(WIRELESS_INTERFACE_DEFAULT);       // Set default wireless interface information
    set_hapd_full_exec_path(HAPD_EXEC_FILE_DEFAULT);          // Set default hostapd execution file path
    set_hapd_ctrl_path(HAPD_CTRL_PATH_DEFAULT);               // Set default hostapd control interface path
    set_hapd_global_ctrl_path(HAPD_GLOBAL_CTRL_PATH_DEFAULT); // Set default hostapd global control interface path
    set_hapd_conf_file(HAPD_CONF_FILE_DEFAULT);               // Set default hostapd configuration file path
    set_wpas_full_exec_path(WPAS_EXEC_FILE_DEFAULT);          // Set default wap_supplicant execution file path
    set_wpas_ctrl_path(WPAS_CTRL_PATH_DEFAULT);               // Set default wap_supplicant control interface path
    set_wpas_global_ctrl_path(WPAS_GLOBAL_CTRL_PATH_DEFAULT); // Set default wap_supplicant global control interface path
    set_wpas_conf_file(WPAS_CONF_FILE_DEFAULT);               // Set default wap_supplicant configuration file path

    /* Parse the application arguments */
    if (parse_parameters(argc, argv)) {
        return 0;
    }

#ifndef _OPENWRT_
    system("mkdir -p /etc/hostapd/");
#endif

    /* Print the run-time information */
    indigo_logger(LOG_LEVEL_INFO, "QuickTrack control app running at: %d", get_service_port());
    indigo_logger(LOG_LEVEL_INFO, "Wireless Interface:" );
    show_wireless_interface_info();
    indigo_logger(LOG_LEVEL_INFO, "hostapd Path: %s (%s)", get_hapd_full_exec_path(), get_hapd_exec_file());
    indigo_logger(LOG_LEVEL_INFO, "wpa_supplicant Path: %s (%s)", get_wpas_full_exec_path(), get_wpas_exec_file());

    /*
     * The following information may not help anymore since
     * - we support multiple vaps
     * - remote udp port is known only when receive the control interface TLV
    indigo_logger(LOG_LEVEL_INFO, "Hostapd Global Control Interface: %s", get_hapd_global_ctrl_path());
    indigo_logger(LOG_LEVEL_INFO, "Hostapd Control Interface: %s", get_hapd_ctrl_path());
    indigo_logger(LOG_LEVEL_INFO, "WPA Supplicant Control Interface: %s", get_wpas_ctrl_path());
    */

    /* Register the callback */
    register_apis();

    /* Intiate the vendor's specific startup commands */
    vendor_init();

    /* Start eloop */
    qt_eloop_init(NULL);

    /* Register SIGTERM */
    qt_eloop_register_signal(SIGINT, handle_term, NULL);
    qt_eloop_register_signal(SIGTERM, handle_term, NULL);

    /* Bind the service port and register to eloop */
    service_socket = control_socket_init(get_service_port());
    if (service_socket >= 0) {
        qt_eloop_run();
    } else {
        indigo_logger(LOG_LEVEL_INFO, "Failed to initiate the UDP socket");
    }

    /* Stop eloop */
    qt_eloop_destroy();
    indigo_logger(LOG_LEVEL_INFO, "ControlAppC stops");
    if (service_socket >= 0) {
        indigo_logger(LOG_LEVEL_INFO, "Close service port: %d", get_service_port());
        close(service_socket);
    }

    return 0;
}
