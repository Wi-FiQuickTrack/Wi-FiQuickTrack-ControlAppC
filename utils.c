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
#ifdef _OPENWRT_
#include <sys/time.h>
#endif
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "vendor_specific.h"
#include "utils.h"
#include "eloop.h"

/* Log */
int stdout_level = LOG_LEVEL_DEBUG;
int syslog_level = LOG_LEVEL_INFO;

/* multiple VAPs */
int interface_count = 0;
struct interface_info interfaces[8];
int bss_id[3] = {0, 0, 0}; // 2.4G, 5G, Dual Band

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

/* System */
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

char* read_file(char *fn) {
    struct stat st;
    int fd, size;
    char *buffer = NULL;

    memset(&st, 0, sizeof(struct stat));
    stat(fn, &st);
    size = st.st_size;

    fd = open(fn, O_RDONLY);
    if (fd) {
        buffer = (char*)malloc(sizeof(char)*size);
        read(fd, buffer, size);
    }
    return buffer;
}

int write_file(char *fn, char *buffer, int len) {
    int fd;

    fd = open(fn, O_CREAT | O_WRONLY | O_TRUNC);
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
    indigo_logger(LOG_LEVEL_INFO, "Loopback Client starts ip %s port %u", local_ip, local_port);

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

int send_loopback_data(char *target_ip, int target_port, int packet_count, int packet_size, int rate) {
    int s = 0, i = 0;
    struct sockaddr_in addr;
    int pkt_sent = 0, pkt_rcv = 0;
    char message[1600], server_reply[1600];
    ssize_t recv_len = 0, send_len = 0;

    /* Open UDP socket */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open socket");
        return -1;
    }

    struct timeval timeout = {3, 0}; //3s
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (target_ip) {
        addr.sin_addr.s_addr = inet_addr(target_ip);
    }
    addr.sin_port = htons(target_port);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Connect failed. Error");
        close(s);
        return -1;
    }

    memset(&message, 0, sizeof(message));
    for (i = 0; (i < packet_size) && (i < sizeof(message)); i++)
        message[i] = 0x0A;

    for (pkt_sent = 0; pkt_sent < packet_count; pkt_sent++) {
        memset(&server_reply, 0, sizeof(server_reply));

        send_len = send(s, message, strlen(message), 0);
        if (send_len < 0)
        {
            indigo_logger(LOG_LEVEL_INFO, "Send failed on packet %d", pkt_sent);
            continue;
        }
        indigo_logger(LOG_LEVEL_INFO, "Packet %d: Send loopback %d bytes data to ip %s port %u",
                      pkt_sent, send_len, target_ip, target_port);

        recv_len = recv(s, server_reply, sizeof(server_reply), 0);
        if (recv_len < 0)
        {
            indigo_logger(LOG_LEVEL_INFO, "recv failed on packet %d", pkt_sent);
            continue;
        }
        pkt_rcv++;
        sleep(rate);

        indigo_logger(LOG_LEVEL_INFO, "Receive echo %d bytes data", recv_len);
    }
    close(s);

    return pkt_rcv;
}

int send_broadcast_arp(char *target_ip, int *send_count, int rate) {
    char buffer[S_BUFFER_LEN];
    FILE *fp;
    int recv = 0;

    snprintf(buffer, sizeof(buffer), "arping -i %s %s -c %d -W %d | grep packet", get_wireless_interface(), target_ip, *send_count, rate);
    fp = popen(buffer, "r");
    if (fp == NULL)
        return 0;
    //arping output format: 1 packets transmitted, 1 packets received,   0% unanswered (0 extra)
    fscanf(fp, "%d %*s %*s %d", &recv , send_count);
    pclose(fp);

    return recv;
}

int find_interface_ip(char *ipaddr, int ipaddr_len, char *name) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr = NULL;

    getifaddrs(&ifap);
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

int bridge_created = 0;

int is_bridge_created() {
    return bridge_created;
}

int create_bridge(char *br) {
    char cmd[S_BUFFER_LEN];

    /* Create new bridge */
    sprintf(cmd, "brctl addbr %s", br);
    system(cmd);

    /* Bring up bridge */
    sprintf(cmd, "ifconfig %s up", br);
    system(cmd);

    bridge_created = 1;

    return 0;
}

int add_interface_to_bridge(char *br, char *ifname) {
    char cmd[S_BUFFER_LEN];

    /* Reset IP address */
    sprintf(cmd, "ifconfig %s 0.0.0.0", ifname);
    system(cmd);

    /* Add interface to bridge */
    sprintf(cmd, "brctl addif %s %s", br, ifname);
    system(cmd);
    printf("%s\n", cmd);

    return 0;
}

int reset_bridge(char *br) {
    char cmd[S_BUFFER_LEN];

    /* Bring down bridge */
    sprintf(cmd, "ifconfig %s down", br);
    system(cmd);
    sprintf(cmd, "brctl delbr %s", br);
    system(cmd);
 
    bridge_created = 0;

    return 0;
}

int add_wireless_interface(char *ifname) {
    char cmd[S_BUFFER_LEN];

    sprintf(cmd, "iw dev %s interface add %s type managed", get_wireless_interface(), ifname);
    system(cmd);

    return 0;
}

int delete_wireless_interface(char *ifname) {
    char cmd[S_BUFFER_LEN];

    sprintf(cmd, "iw dev %s del", ifname);
    system(cmd);

    return 0;
}

int control_interface(char *ifname, char *op) {
    char cmd[S_BUFFER_LEN];

    sprintf(cmd, "ip link set %s %s", ifname, op);
    system(cmd);
 
    return 0;
}

int set_interface_ip(char *ifname, char *ip) {
    char cmd[S_BUFFER_LEN];

    sprintf(cmd, "ifconfig %s %s", ifname, ip);
    system(cmd);
 
    return 0;
}

int add_all_wireless_interface_to_bridge(char *br) {
    int i;

    for (i = 0; i < interface_count; i++) {
        control_interface(interfaces[i].ifname, "up");
        add_interface_to_bridge(br, interfaces[i].ifname);
    }

    return 0;
}
/* Environment */
int service_port = SERVICE_PORT_DEFAULT;

char hapd_ctrl_path[64] = HAPD_CTRL_PATH_DEFAULT;
char hapd_full_ctrl_path[128];
char hapd_global_ctrl_path[64] = HAPD_GLOBAL_CTRL_PATH_DEFAULT;
char hapd_conf_file[64] = HAPD_CONF_FILE_DEFAULT;

char wpas_ctrl_path[64] = WPAS_CTRL_PATH_DEFAULT;
char wpas_full_ctrl_path[128];
char wpas_global_ctrl_path[64] = WPAS_GLOBAL_CTRL_PATH_DEFAULT;
char wpas_conf_file[64] = WPAS_CONF_FILE_DEFAULT;

struct interface_info* get_wireless_interface_info(int band, int identifier) {
    int i;

    for (i = 0; i < interface_count; i++) {
        if ((interfaces[i].band == BAND_DUAL || interfaces[i].band == band) && 
             (interfaces[i].identifier == identifier)) {
            return &interfaces[i];
        }
    }

    return NULL;
}

char* get_wireless_interface_name_by_id(int identifier) {
    int i;

    for (i = 0; i < interface_count; i++) {
        if (identifier >= 0 && interfaces[i].identifier == identifier) {
            return interfaces[i].ifname;
        }
    }

    return NULL;
}

char* get_hapd_ctrl_path_by_id(int identifier) {
    memset(hapd_full_ctrl_path, 0, sizeof(hapd_full_ctrl_path));
    if (identifier >= 0) {
        sprintf(hapd_full_ctrl_path, "%s/%s", hapd_ctrl_path, get_wireless_interface_name_by_id(identifier));
    }
    else {
        sprintf(hapd_full_ctrl_path, "%s/%s", hapd_ctrl_path, get_default_wireless_interface_info());
    }
    printf("hapd_full_ctrl_path: %s\n", hapd_full_ctrl_path);
    return hapd_full_ctrl_path;
}

char* get_hapd_ctrl_path() {
    memset(hapd_full_ctrl_path, 0, sizeof(hapd_full_ctrl_path));
    sprintf(hapd_full_ctrl_path, "%s/%s", hapd_ctrl_path, get_default_wireless_interface_info());
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

char* get_hapd_conf_file() {
    return hapd_conf_file;
}

int set_hapd_conf_file(char* path) {
    memset(hapd_conf_file, 0, sizeof(hapd_conf_file));
    snprintf(hapd_conf_file, sizeof(hapd_conf_file), "%s", path);
    return 0;
}

char* get_wpas_ctrl_path() {
    memset(wpas_full_ctrl_path, 0, sizeof(wpas_full_ctrl_path));
    sprintf(wpas_full_ctrl_path, "%s/%s", wpas_ctrl_path, get_default_wireless_interface_info());
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

char* get_wpas_conf_file() {
    return wpas_conf_file;
}

int set_wpas_conf_file(char* path) {
    memset(wpas_conf_file, 0, sizeof(wpas_conf_file));
    snprintf(wpas_conf_file, sizeof(wpas_conf_file), "%s", path);
    return 0;
}


int add_wireless_interface_info(int band, int bssid, char *name) {
    interfaces[interface_count].band = band;
    interfaces[interface_count].bssid = -1;
    interfaces[interface_count].identifier = ++bss_id[band];
    strcpy(interfaces[interface_count++].ifname, name);
    return 0;
}

int show_wireless_interface_info() {
    int i;
    char *band;
    printf("interface_count=%d\n", interface_count);

    for (i = 0; i < interface_count; i++) {
        if (interfaces[i].band == BAND_24GHZ) {
            band = "2.4GHz";
        } else if (interfaces[i].band == BAND_5GHZ) {
            band = "5GHz";
        } else {
            band = "Dual";
        }

        printf("Interface Name: %s, Band: %s, BSSID: %d identifier %d\n", 
            interfaces[i].ifname, band, interfaces[i].bssid, interfaces[i].identifier);
    }
    return 0;
}

int parse_wireless_interface_info(char *info) {
    char *token = NULL;
    char *delimit = ",";

    token = strtok(info, delimit);
  
    while(token != NULL) {
        if (strncmp(token, "2:", 2) == 0) {
            add_wireless_interface_info(BAND_24GHZ, -1, token+2);
        } else if (strncmp(token, "5:", 2) == 0) {
            add_wireless_interface_info(BAND_5GHZ, -1, token+2);
        } else if (strncmp(token, "d:", 2) == 0) {
            add_wireless_interface_info(BAND_DUAL, -1, token+2);
        } else {
            return -1;
        }
        token = strtok(NULL, delimit);
    }    

    return 0;
}

char* get_default_wireless_interface_info() {
    return interfaces[0].ifname;
}

struct interface_info* get_wireless_interface_info_by_band(int band) {
    int i;

    for (i = 0; i < interface_count; i++) {
        if (interfaces[i].band == BAND_DUAL || interfaces[i].band == band) {
            return &interfaces[i];
        }
    }

    return NULL;
}

struct interface_info* get_avail_wireless_interface(int band) {
    int i;

    for (i = 0; i < interface_count; i++) {
        if ((interfaces[i].identifier == -1) && (interfaces[i].band == BAND_DUAL || interfaces[i].band == band)) {
            return &interfaces[i];
        }
    }

    return NULL;
}

/* Parse BSS IDENTIFIER TLV */
void parse_bss_identifier(int bss_identifier, struct bss_identifier_info* bss) {
    bss->band = bss_identifier & 0x07;
    bss->mbssid_enable = (bss_identifier & 0x08) >> 3;
    bss->transmitter = (bss_identifier & 0x10) >> 4;
    bss->identifier = (bss_identifier & 0xE0) >> 5;
    return;
}

void set_wireless_interface_resource(struct interface_info* wlan, int identifier) {
    //wlan->identifier = identifier;
    memset(wlan->hapd_conf_file, 0, sizeof(wlan->hapd_conf_file));
    snprintf(wlan->hapd_conf_file, sizeof(wlan->hapd_conf_file), "%s/hostapd-%d.conf", HAPD_CONF_FILE_DEFAULT_PATH, identifier);
    show_wireless_interface_info();
}

void clear_interfaces_resource() {
    int i, err = 0;
    for (i = 0; i < interface_count; i++)
    {
        //interfaces[i].identifier = -1;
        err = unlink(interfaces[i].hapd_conf_file);
        if (err)
        {
            indigo_logger(LOG_LEVEL_DEBUG, "Failed to remove %s", interfaces[i].hapd_conf_file);
        }
    }

    return ;
}

char* get_all_hapd_conf_files() {
    int i, valid_id_cnt = 0;
    static char conf_files[128];

    memset(conf_files, 0, sizeof(conf_files));
    for (i = 0; i < interface_count; i++) {
        if (interfaces[i].identifier != -1) {
            valid_id_cnt++;
            strncat(conf_files, interfaces[i].hapd_conf_file, strlen(interfaces[i].hapd_conf_file));
            strncat(conf_files, " ", 1);
        }
    }
    if (valid_id_cnt)
        return conf_files;
    else
        return hapd_conf_file;
}

char* get_wireless_interface() {
    return get_default_wireless_interface_info();
}

int set_wireless_interface(char *name) {
    memset(interfaces, 0, sizeof(interfaces));
    interface_count = 0;

    if (strstr(name, ":")) {
        parse_wireless_interface_info(name);
    } else {
        add_wireless_interface_info(BAND_DUAL, -1, name);
    }
    return 0;
}

int get_service_port() {
    return service_port;
}

int set_service_port(int port) {
    service_port = port;
    return 0;
}

struct channel_info band_24[] = { {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427}, {5, 2432}, {6, 2437}, {7, 2442}, {8, 2447}, {9, 2452}, {10, 2457}, {11, 2462} };
struct channel_info band_5[] = { {36, 5180}, {40, 5200}, {44, 5220}, {48, 5240}, {52, 5260}, {56, 5280}, {60, 5300}, {64, 5320}, {100, 5500}, {104, 5520}, {108, 5540}, 
                                 {112, 5560}, {116, 5580}, {120, 5600}, {124, 5620}, {128, 5640}, {132, 5660}, {136, 5680}, {140, 5700}, {144, 5720}, {149, 5745}, 
                                 {153, 5765}, {157, 5785}, {161, 5805}, {165, 8525} };

int verify_band_from_freq(int freq, int band) {
    struct channel_info *info = NULL;
    int i, size = 0;

    if (band == BAND_24GHZ) {
        info = band_24;
        size = sizeof(band_24)/sizeof(struct channel_info);
    } else {
        info = band_5;
        size = sizeof(band_5)/sizeof(struct channel_info);
    }

    for (i = 0; i < size; i++) {
        if (freq == info[i].freq) {
            return 0;
        }
    }

    return -1;
}

/* String operation */
size_t strlcpy(char *dest, const char *src, size_t siz) {
	const char *s = src;
	size_t left = siz;

	if (left) {
		/* Copy string up to the maximum size of the dest buffer */
		while (--left != 0) {
			if ((*dest++ = *s++) == '\0')
				break;
		}
	}

	if (left == 0) {
		/* Not enough room for the string; force NUL-termination */
		if (siz != 0)
			*dest = '\0';
		while (*s++)
			; /* determine total src string length */
	}

	return s - src - 1;
}

int get_key_value(char *value, char *buffer, char *token) {
    char *ptr = NULL, *endptr = NULL;
    char _token[S_BUFFER_LEN];

    if (!value || !buffer || !token) {
        return -1;
    }

    memset(_token, 0, sizeof(_token));
    sprintf(_token, "\n%s=", token);
    ptr = strstr(buffer, _token);
    if (!ptr) {
        sprintf(_token, "%s=", token);
        if (strncmp(buffer, _token, strlen(_token)) == 0) {
            ptr = buffer;
        }
    }

    if (!ptr) {
        return -1;
    }

    ptr += strlen(_token);
    endptr = strstr(ptr, "\n");
    if (endptr) {
        strncpy(value, ptr, endptr - ptr);
    } else {
        strcpy(value, ptr);
    }

    return 0;
}
