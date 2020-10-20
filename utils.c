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
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "utils.h"
#include "eloop.h"

int stdout_level = LOG_LEVEL_DEBUG;
int syslog_level = LOG_LEVEL_INFO;

void debug_print_timestamp(void) {
    time_t rawtime;
    struct tm *info;
    char buffer[32];

    time(&rawtime);
    info = localtime(&rawtime);
    if (info) {
        strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", info);
    }
    printf("%s ", buffer);
}

void indigo_logger(int level, const char *fmt, ...) {
    char *format, *log_type;
    int maxlen;
    int priority;
    va_list ap;

    maxlen = strlen(fmt) + 100;
    format = malloc(maxlen);
    if (!format) {
        return;
    }

    switch (level) {
    case LOG_LEVEL_DEBUG_VERBOSE:
        log_type = "debugverbose";
        break;
    case LOG_LEVEL_DEBUG:
        log_type = "debug";
        break;
    case LOG_LEVEL_INFO:
        log_type = "info";
        break;
    case LOG_LEVEL_NOTICE:
        log_type = "notice";
        break;
    case LOG_LEVEL_WARNING:
        log_type = "warning";
        break;
    default:
        log_type = "info";
        break;
    }

    snprintf(format, maxlen, "controlappc.%8s  %s", log_type, fmt);

    if (level >= stdout_level) {
        debug_print_timestamp();
        va_start(ap, fmt);
        vprintf(format, ap);
        va_end(ap);
        printf("\n");
    }

    if (level >= stdout_level) {
        switch (level) {
        case LOG_LEVEL_DEBUG_VERBOSE:
        case LOG_LEVEL_DEBUG:
                priority = LOG_DEBUG;
                break;
        case LOG_LEVEL_INFO:
                priority = LOG_INFO;
                break;
        case LOG_LEVEL_NOTICE:
                priority = LOG_NOTICE;
                break;
        case LOG_LEVEL_WARNING:
                priority = LOG_WARNING;
                break;
        default:
                priority = LOG_INFO;
                break;
        }
        va_start(ap, fmt);
        vsyslog(priority, format, ap);
        va_end(ap);
    }
}

int pipe_command(char *buffer, int buffer_size, char *cmd, char *parameter[]) {
    int pipefds[2], len;
    pid_t pid;

    if (pipe(pipefds) == -1){
        indigo_logger(LOG_LEVEL_ERROR, "Failed to create the pipe");
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to fork");
        return -1;
    }

    if (pid == 0) {
        // Replace stdout with the write end of the pipe
        dup2(pipefds[1], STDOUT_FILENO);  
        // Close read to pipe, in child
        close(pipefds[0]);
        execv(cmd, parameter);
        exit(EXIT_SUCCESS);
    } else {
        close(pipefds[1]);
        len = read(pipefds[0], buffer, buffer_size);
        indigo_logger(LOG_LEVEL_DEBUG_VERBOSE, "Pipe system call= %s, Return length= %d, result= %s", cmd, len, buffer);
        close(pipefds[0]);
    }
    return len;
}

int write_file(char *fn, char *buffer, int len) {
    int fd;

    fd = open(fn, O_CREAT | O_WRONLY);
    if (fd > 0) {
        (void)write(fd, buffer, len);
        close(fd);
        return 0;
    }

    return -1;
}

/* Loopback */
int loopback_socket = 0;

static void loopback_client_receive_message(int sock, void *eloop_ctx, void *sock_ctx) {
    struct sockaddr_storage from;
    unsigned char buffer[BUFFER_LEN];
    int fromlen, len;

    fromlen = sizeof(from);
    len = recvfrom(sock, buffer, BUFFER_LEN, 0, (struct sockaddr *) &from, &fromlen);
    if (len < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Loopback Client recvfrom[server] error");
        return ;
    }

    indigo_logger(LOG_LEVEL_INFO, "Loopback Client received length = %d", len);

    len = sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (struct sockaddr *)&from, sizeof(from));

    indigo_logger(LOG_LEVEL_INFO, "Loopback Client echo back length = %d", len);
}

static void loopback_client_timeout(void *eloop_ctx, void *timeout_ctx) {
    int s = (intptr_t)eloop_ctx;
    eloop_unregister_read_sock(s);
    close(s);
    loopback_socket = 0;
    indigo_logger(LOG_LEVEL_INFO, "Loopback Client stops");
}

int loopback_client_start(char *target_ip, int target_port, char *local_ip, int local_port, int timeout) {
    int s = 0;
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
    if (local_ip) {
        addr.sin_addr.s_addr = inet_addr(local_ip);
    }
    addr.sin_port = htons(local_port);
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to bind server socket");
        close(s);
        return -1;
    }

    /* Register to eloop and ready for the socket event */
    if (eloop_register_read_sock(s, loopback_client_receive_message, NULL, NULL)) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to initiate ControlAppC");
        return -1;
    }
    loopback_socket = s;
    eloop_register_timeout(timeout, 0, loopback_client_timeout, (void*)(intptr_t)s, NULL);
    indigo_logger(LOG_LEVEL_INFO, "Loopback Client starts");

    return 0;
}

int loopback_client_stop() {
    if (loopback_socket) {
        eloop_cancel_timeout(loopback_client_timeout, (void*)(intptr_t)loopback_socket, NULL);
        eloop_unregister_read_sock(loopback_socket);
        close(loopback_socket);
        loopback_socket = 0;
    }
    return 0;
}

int loopback_client_status() {
    return !!loopback_socket;
}

int find_interface_ip(char *ipaddr, int ipaddr_len, char *name) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr = NULL;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, name) == 0) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            if (ipaddr) {
                strcpy(ipaddr, addr);
            }
            return 1;
        }
    }
    freeifaddrs(ifap);
    return 0;
}

int get_mac_address(char *buffer, int size, char *interface) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", 
            (char)s.ifr_addr.sa_data[0]&0x00ff, (char)s.ifr_addr.sa_data[1]&0x00ff, (char)s.ifr_addr.sa_data[2]&0x00ff, 
            (char)s.ifr_addr.sa_data[3]&0x00ff, (char)s.ifr_addr.sa_data[4]&0x00ff, (char)s.ifr_addr.sa_data[5]&0x00ff);
        return 0;
    }
    return 1;
}

/* Environment */
int service_port = SERVICE_PORT_DEFAULT;
char wireless_interface[64] = WIRELESS_INTERFACE_DEFAULT;

char hapd_ctrl_path[64] = HAPD_CTRL_PATH_DEFAULT;
char hapd_full_ctrl_path[128];
char hapd_global_ctrl_path[64] = HAPD_GLOBAL_CTRL_PATH_DEFAULT;

char wpas_ctrl_path[64] = WPAS_CTRL_PATH_DEFAULT;
char wpas_full_ctrl_path[128];
char wpas_global_ctrl_path[64] = WPAS_GLOBAL_CTRL_PATH_DEFAULT;

char* get_hapd_ctrl_path() {
    memset(hapd_full_ctrl_path, 0, sizeof(hapd_full_ctrl_path));
    sprintf(hapd_full_ctrl_path, "%s/%s", hapd_ctrl_path, wireless_interface);
    return hapd_full_ctrl_path;
}

int set_hapd_ctrl_path(char* path) {
    memset(hapd_ctrl_path, 0, sizeof(hapd_ctrl_path));
    snprintf(hapd_ctrl_path, sizeof(hapd_ctrl_path), "%s", path);
    return 0;
}

char* get_hapd_global_ctrl_path() {
    return hapd_global_ctrl_path;
}

int set_hapd_global_ctrl_path(char* path) {
    memset(hapd_global_ctrl_path, 0, sizeof(hapd_global_ctrl_path));
    snprintf(hapd_global_ctrl_path, sizeof(hapd_global_ctrl_path), "%s", path);
    return 0;
}

char* get_wpas_ctrl_path() {
    memset(wpas_full_ctrl_path, 0, sizeof(wpas_full_ctrl_path));
    sprintf(wpas_full_ctrl_path, "%s/%s", wpas_ctrl_path, wireless_interface);
    return wpas_full_ctrl_path;
}

int set_wpas_ctrl_path(char* path) {
    snprintf(wpas_ctrl_path, sizeof(wpas_ctrl_path), "%s", path);
    return 0;
}

char* get_wpas_global_ctrl_path() {
    return wpas_global_ctrl_path;
}

int set_wpas_global_ctrl_path(char* path) {
    snprintf(wpas_global_ctrl_path, sizeof(wpas_global_ctrl_path), "%s", path);
    return 0;
}

char* get_wireless_interface() {
    return wireless_interface;
}

int set_wireless_interface(char *name) {
    snprintf(wireless_interface, sizeof(wireless_interface), "%s", name);
    return 0;
}

int get_service_port() {
    return service_port;
}

int set_service_port(int port) {
    service_port = port;
    return 0;
}
