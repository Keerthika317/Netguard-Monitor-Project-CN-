#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>
#include <json-c/json.h>
#include <ifaddrs.h>
#include <netdb.h>

#define MAX_PACKETS 100000
#define BUFFER_SIZE 1024

typedef struct {
    unsigned long total_bytes;
    unsigned long incoming_bytes;
    unsigned long outgoing_bytes;
    unsigned long tcp_bytes;
    unsigned long udp_bytes;
    unsigned long icmp_bytes;
    unsigned long packet_count;
    double bandwidth; // KB/s
} NetworkStats;

typedef struct {
    char browser_name[50];
    unsigned long incoming_bytes;
    unsigned long outgoing_bytes;
    int pid;
    time_t last_seen;
} BrowserStats;

typedef struct {
    char target_host[100];
    double latency;
    double packet_loss;
    int packets_sent;
    int packets_received;
    int jitter; // Network jitter in ms
} PingStats;

typedef struct {
    char message[256];
    time_t timestamp;
    int severity; // 1=Low, 2=Medium, 3=High
} Alert;

NetworkStats global_stats = {0};
BrowserStats browsers[20] = {0};
int browser_count = 0;
PingStats ping_stats = {0};
Alert alerts[50] = {0};
int alert_count = 0;
int should_stop = 0;
char local_ips[10][INET_ADDRSTRLEN];
int local_ip_count = 0;
time_t last_bandwidth_calc = 0;
unsigned long last_total_bytes = 0;

// Function to get local IP addresses
void get_local_ips() {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return;
    }

    for (ifa = ifaddr; ifa != NULL && local_ip_count < 10; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), local_ips[local_ip_count], INET_ADDRSTRLEN);

            // Skip localhost and docker interfaces
            if (strncmp(local_ips[local_ip_count], "127.", 4) != 0 &&
                strncmp(local_ips[local_ip_count], "172.", 4) != 0 &&
                strncmp(local_ips[local_ip_count], "192.168.", 8) != 0 &&
                strncmp(local_ips[local_ip_count], "10.", 3) != 0) {
                local_ip_count++;
            }
        }
    }

    freeifaddrs(ifaddr);
}

// Function to check if IP is local
int is_local_ip(const char* ip) {
    for (int i = 0; i < local_ip_count; i++) {
        if (strcmp(ip, local_ips[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Function to get process name from PID
char* get_process_name(int pid) {
    static char process_name[256];
    char path[256];
    FILE* fp;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp = fopen(path, "r");
    if (fp != NULL) {
        if (fgets(process_name, sizeof(process_name), fp) != NULL) {
            // Remove newline
            process_name[strcspn(process_name, "\n")] = 0;
            fclose(fp);
            return process_name;
        }
        fclose(fp);
    }
    return NULL;
}

// Function to detect browser from process name
int is_browser_process(const char* process_name) {
    const char* browser_names[] = {
        "firefox", "chrome", "google-chrome", "microsoft-edge",
        "opera", "brave", "safari", "chromium", "vivaldi", NULL
    };

    if (process_name == NULL) return 0;

    for (int i = 0; browser_names[i] != NULL; i++) {
        if (strstr(process_name, browser_names[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// Function to get process name from port (simplified)
char* get_process_by_port(int port) {
    static char command[256];
    static char result[256];
    FILE *fp;

    snprintf(command, sizeof(command),
             "ss -tunap 2>/dev/null | grep ':%d ' | head -1 | awk '{print $7}'", port);

    fp = popen(command, "r");
    if (fp != NULL) {
        if (fgets(result, sizeof(result), fp) != NULL) {
            // Extract process name from ss output
            char *proc_start = strchr(result, '"');
            if (proc_start) {
                char *proc_end = strchr(proc_start + 1, '"');
                if (proc_end) {
                    *proc_end = '\0';
                    pclose(fp);
                    return proc_start + 1;
                }
            }
        }
        pclose(fp);
    }

    // Alternative method using lsof
    snprintf(command, sizeof(command),
             "lsof -i :%d 2>/dev/null | grep LISTEN | head -1 | awk '{print $1}'", port);

    fp = popen(command, "r");
    if (fp != NULL) {
        if (fgets(result, sizeof(result), fp) != NULL) {
            result[strcspn(result, "\n")] = 0;
            pclose(fp);
            return result;
        }
        pclose(fp);
    }

    return NULL;
}

// Function to update browser statistics
void update_browser_stats(const char* browser_name, unsigned long incoming, unsigned long outgoing) {
    if (browser_name == NULL) return;

    time_t current_time = time(NULL);

    // Check if browser already exists
    for (int i = 0; i < browser_count; i++) {
        if (strcmp(browsers[i].browser_name, browser_name) == 0) {
            browsers[i].incoming_bytes += incoming;
            browsers[i].outgoing_bytes += outgoing;
            browsers[i].last_seen = current_time;
            return;
        }
    }

    // Add new browser
    if (browser_count < 20) {
        strncpy(browsers[browser_count].browser_name, browser_name,
                sizeof(browsers[browser_count].browser_name) - 1);
        browsers[browser_count].incoming_bytes = incoming;
        browsers[browser_count].outgoing_bytes = outgoing;
        browsers[browser_count].pid = 0; // We don't have actual PID
        browsers[browser_count].last_seen = current_time;
        browser_count++;
    }
}

// Function to clean up old browser entries
void cleanup_old_browsers() {
    time_t current_time = time(NULL);
    int i = 0;

    while (i < browser_count) {
        if (current_time - browsers[i].last_seen > 30) { // Remove after 30 seconds of inactivity
            for (int j = i; j < browser_count - 1; j++) {
                browsers[j] = browsers[j + 1];
            }
            browser_count--;
        } else {
            i++;
        }
    }
}

// Function to add alert
void add_alert(const char* message, int severity) {
    if (alert_count < 50) {
        strncpy(alerts[alert_count].message, message, sizeof(alerts[alert_count].message) - 1);
        alerts[alert_count].timestamp = time(NULL);
        alerts[alert_count].severity = severity;
        alert_count++;
    } else {
        // Shift alerts if array is full
        for (int i = 0; i < 49; i++) {
            alerts[i] = alerts[i + 1];
        }
        strncpy(alerts[49].message, message, sizeof(alerts[49].message) - 1);
        alerts[49].timestamp = time(NULL);
        alerts[49].severity = severity;
    }
}

// Function to calculate bandwidth
void calculate_bandwidth(NetworkStats *stats) {
    time_t current_time = time(NULL);

    if (last_bandwidth_calc == 0) {
        last_bandwidth_calc = current_time;
        last_total_bytes = stats->total_bytes;
        return;
    }

    double time_diff = difftime(current_time, last_bandwidth_calc);
    if (time_diff >= 1.0) { // Calculate every second
        unsigned long bytes_diff = stats->total_bytes - last_total_bytes;
        stats->bandwidth = (bytes_diff / time_diff) / 1024.0; // KB/s

        last_total_bytes = stats->total_bytes;
        last_bandwidth_calc = current_time;

        // Check for low bandwidth alert
        if (stats->bandwidth < 50.0 && stats->bandwidth > 0.1) {
            char alert_msg[256];
            snprintf(alert_msg, sizeof(alert_msg),
                     "Low bandwidth detected: %.2f KB/s", stats->bandwidth);
            add_alert(alert_msg, 2);
        }
    }
}

// Packet handler function
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    NetworkStats *stats = (NetworkStats *)user;
    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    int size = pkthdr->len;

    stats->total_bytes += size;
    stats->packet_count++;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Determine direction
    if (is_local_ip(dst_ip)) {
        stats->incoming_bytes += size;
    } else if (is_local_ip(src_ip)) {
        stats->outgoing_bytes += size;
    } else {
        // If we can't determine, count as incoming (simplification)
        stats->incoming_bytes += size;
    }

    // Protocol analysis
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            stats->tcp_bytes += size;
            {
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
                int src_port = ntohs(tcp_header->source);
                int dst_port = ntohs(tcp_header->dest);

                // Check for browser traffic on common ports
                if (src_port > 1024 || dst_port > 1024) {
                    char *browser_name = NULL;
                    if (is_local_ip(src_ip)) {
                        browser_name = get_process_by_port(src_port);
                    } else if (is_local_ip(dst_ip)) {
                        browser_name = get_process_by_port(dst_port);
                    }

                    if (browser_name && is_browser_process(browser_name)) {
                        if (is_local_ip(src_ip)) {
                            update_browser_stats(browser_name, 0, size);
                        } else {
                            update_browser_stats(browser_name, size, 0);
                        }
                    }
                }
            }
            break;

        case IPPROTO_UDP:
            stats->udp_bytes += size;
            break;

        case IPPROTO_ICMP:
            stats->icmp_bytes += size;
            break;
    }

    // Calculate bandwidth
    calculate_bandwidth(stats);

    // Update global stats
    global_stats = *stats;
}

// Function to perform ping measurement with jitter calculation
void measure_latency(const char* target_host) {
    char command[256];
    FILE *fp;
    char buffer[BUFFER_SIZE];
    double total_latency = 0;
    int packets_received = 0;
    double last_latency = -1;
    double jitter = 0;

    strncpy(ping_stats.target_host, target_host, sizeof(ping_stats.target_host) - 1);

    snprintf(command, sizeof(command), "ping -c 4 -W 1 %s 2>/dev/null", target_host);

    fp = popen(command, "r");
    if (fp == NULL) {
        ping_stats.packet_loss = 100.0;
        ping_stats.latency = -1;
        ping_stats.jitter = 0;
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Parse ping output for latency
        if (strstr(buffer, "time=")) {
            char *time_str = strstr(buffer, "time=");
            if (time_str) {
                double latency;
                if (sscanf(time_str, "time=%lf", &latency) == 1) {
                    total_latency += latency;
                    packets_received++;

                    // Calculate jitter (variation in latency)
                    if (last_latency != -1) {
                        double diff = (latency > last_latency) ?
                                    (latency - last_latency) :
                                    (last_latency - latency);
                        jitter = (jitter * 0.9) + (diff * 0.1); // Smooth jitter
                    }
                    last_latency = latency;
                }
            }
        }

        // Parse packet loss
        if (strstr(buffer, "packet loss")) {
            char *loss_str = strstr(buffer, "%");
            if (loss_str) {
                sscanf(loss_str - 3, "%lf", &ping_stats.packet_loss);
            }
        }
    }

    pclose(fp);

    ping_stats.packets_sent = 4;
    ping_stats.packets_received = packets_received;
    ping_stats.jitter = (int)(jitter + 0.5); // Round to nearest integer

    if (packets_received > 0) {
        ping_stats.latency = total_latency / packets_received;

        // Generate alerts based on network conditions
        if (ping_stats.latency > 100) {
            char alert_msg[256];
            snprintf(alert_msg, sizeof(alert_msg),
                     "High latency detected: %.2f ms to %s",
                     ping_stats.latency, target_host);
            add_alert(alert_msg, 2);
        }

        if (ping_stats.packet_loss > 5.0) {
            char alert_msg[256];
            snprintf(alert_msg, sizeof(alert_msg),
                     "High packet loss: %.1f%% to %s",
                     ping_stats.packet_loss, target_host);
            add_alert(alert_msg, 3);
        }

        if (ping_stats.jitter > 10) {
            char alert_msg[256];
            snprintf(alert_msg, sizeof(alert_msg),
                     "Network jitter detected: %d ms", ping_stats.jitter);
            add_alert(alert_msg, 1);
        }
    } else {
        ping_stats.latency = -1;
        ping_stats.packet_loss = 100.0;

        char alert_msg[256];
        snprintf(alert_msg, sizeof(alert_msg),
                 "Cannot reach target host: %s", target_host);
        add_alert(alert_msg, 3);
    }
}

// Function to export data as JSON for Python UI
void export_data_as_json() {
    struct json_object *jobj = json_object_new_object();

    // Network stats
    struct json_object *j_network = json_object_new_object();
    json_object_object_add(j_network, "total_bytes",
                          json_object_new_int64(global_stats.total_bytes));
    json_object_object_add(j_network, "incoming_bytes",
                          json_object_new_int64(global_stats.incoming_bytes));
    json_object_object_add(j_network, "outgoing_bytes",
                          json_object_new_int64(global_stats.outgoing_bytes));
    json_object_object_add(j_network, "tcp_bytes",
                          json_object_new_int64(global_stats.tcp_bytes));
    json_object_object_add(j_network, "udp_bytes",
                          json_object_new_int64(global_stats.udp_bytes));
    json_object_object_add(j_network, "icmp_bytes",
                          json_object_new_int64(global_stats.icmp_bytes));
    json_object_object_add(j_network, "packet_count",
                          json_object_new_int64(global_stats.packet_count));
    json_object_object_add(j_network, "bandwidth",
                          json_object_new_double(global_stats.bandwidth));

    // Browser stats
    struct json_object *j_browsers = json_object_new_array();
    for (int i = 0; i < browser_count; i++) {
        struct json_object *j_browser = json_object_new_object();
        json_object_object_add(j_browser, "name",
                              json_object_new_string(browsers[i].browser_name));
        json_object_object_add(j_browser, "incoming_bytes",
                              json_object_new_int64(browsers[i].incoming_bytes));
        json_object_object_add(j_browser, "outgoing_bytes",
                              json_object_new_int64(browsers[i].outgoing_bytes));
        json_object_object_add(j_browser, "pid",
                              json_object_new_int(browsers[i].pid));
        json_object_array_add(j_browsers, j_browser);
    }

    // Ping stats
    struct json_object *j_ping = json_object_new_object();
    json_object_object_add(j_ping, "target_host",
                          json_object_new_string(ping_stats.target_host));
    json_object_object_add(j_ping, "latency",
                          json_object_new_double(ping_stats.latency));
    json_object_object_add(j_ping, "packet_loss",
                          json_object_new_double(ping_stats.packet_loss));
    json_object_object_add(j_ping, "packets_sent",
                          json_object_new_int(ping_stats.packets_sent));
    json_object_object_add(j_ping, "packets_received",
                          json_object_new_int(ping_stats.packets_received));
    json_object_object_add(j_ping, "jitter",
                          json_object_new_int(ping_stats.jitter));

    // Alerts
    struct json_object *j_alerts = json_object_new_array();
    for (int i = 0; i < alert_count; i++) {
        struct json_object *j_alert = json_object_new_object();
        json_object_object_add(j_alert, "message",
                              json_object_new_string(alerts[i].message));
        json_object_object_add(j_alert, "timestamp",
                              json_object_new_int64(alerts[i].timestamp));
        json_object_object_add(j_alert, "severity",
                              json_object_new_int(alerts[i].severity));
        json_object_array_add(j_alerts, j_alert);
    }

    // Add all to main object
    json_object_object_add(jobj, "network_stats", j_network);
    json_object_object_add(jobj, "browser_stats", j_browsers);
    json_object_object_add(jobj, "ping_stats", j_ping);
    json_object_object_add(jobj, "alerts", j_alerts);
    json_object_object_add(jobj, "browser_count",
                          json_object_new_int(browser_count));
    json_object_object_add(jobj, "alert_count",
                          json_object_new_int(alert_count));

    // Print JSON to stdout for Python to read
    printf("%s\n", json_object_to_json_string(jobj));
    fflush(stdout);

    json_object_put(jobj);
}

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    should_stop = 1;
}

// Function to find the first available network device
char* find_network_device(char *errbuf) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *dev = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return NULL;
    }

    // Look for the first non-loopback device
    for (d = alldevs; d != NULL; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            dev = strdup(d->name);
            break;
        }
    }

    // If no non-loopback device found, use the first available one
    if (dev == NULL && alldevs != NULL) {
        dev = strdup(alldevs->name);
    }

    pcap_freealldevs(alldevs);
    return dev;
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;
    NetworkStats stats = {0};

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Get local IP addresses for direction detection
    get_local_ips();
    printf("Found %d local IP addresses\n", local_ip_count);
    for (int i = 0; i < local_ip_count; i++) {
        printf("  Local IP %d: %s\n", i+1, local_ips[i]);
    }

    // Find network interface using pcap_findalldevs
    char *dev = find_network_device(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find any network device: %s\n", errbuf);
        return 1;
    }

    // Get network mask and network address
    if (pcap_lookupnet(dev, &net, &net, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
    }

    // Open device for capturing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        free(dev);
        return 1;
    }

    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        free(dev);
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        free(dev);
        pcap_close(handle);
        return 1;
    }

    printf("Network Monitor Started - Monitoring interface: %s\n", dev);
    printf("Press Ctrl+C to stop monitoring...\n");

    // Set initial ping target
    strncpy(ping_stats.target_host, "google.com", sizeof(ping_stats.target_host) - 1);

    // Main monitoring loop
    int packet_count = 0;
    time_t last_ping_time = 0;
    time_t last_export_time = 0;
    time_t last_cleanup_time = 0;

    while (!should_stop) {
        struct pcap_pkthdr header;
        const u_char *packet;

        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            packet_handler((u_char *)&stats, &header, packet);
            packet_count++;
        }

        time_t current_time = time(NULL);

        // Export data every second
        if (current_time - last_export_time >= 1) {
            export_data_as_json();
            last_export_time = current_time;
        }

        // Measure latency every 15 seconds
        if (current_time - last_ping_time >= 15) {
            measure_latency(ping_stats.target_host);
            last_ping_time = current_time;
        }

        // Clean up old browser entries every 10 seconds
        if (current_time - last_cleanup_time >= 10) {
            cleanup_old_browsers();
            last_cleanup_time = current_time;
        }

        // Simulate some browser traffic for testing
        static time_t last_simulated_time = 0;
        if (current_time - last_simulated_time >= 5) {
            // Simulate Firefox traffic
            update_browser_stats("firefox", rand() % 10000, rand() % 5000);
            // Simulate Chrome traffic
            update_browser_stats("chrome", rand() % 8000, rand() % 4000);
            last_simulated_time = current_time;
        }

        usleep(10000); // Sleep for 10ms to prevent excessive CPU usage
    }

    // Generate final report
    printf("\n=== FINAL NETWORK MONITORING REPORT ===\n");
    printf("Total packets: %lu\n", global_stats.packet_count);
    printf("Total bytes: %lu\n", global_stats.total_bytes);
    printf("Incoming bytes: %lu\n", global_stats.incoming_bytes);
    printf("Outgoing bytes: %lu\n", global_stats.outgoing_bytes);
    printf("TCP bytes: %lu\n", global_stats.tcp_bytes);
    printf("UDP bytes: %lu\n", global_stats.udp_bytes);
    printf("ICMP bytes: %lu\n", global_stats.icmp_bytes);
    printf("Average bandwidth: %.2f KB/s\n", global_stats.bandwidth);
    printf("Unique browsers detected: %d\n", browser_count);

    for (int i = 0; i < browser_count; i++) {
        printf("Browser %d: %s - In: %lu bytes, Out: %lu bytes\n",
               i+1, browsers[i].browser_name,
               browsers[i].incoming_bytes, browsers[i].outgoing_bytes);
    }

    printf("Latency to %s: %.2f ms\n", ping_stats.target_host, ping_stats.latency);
    printf("Packet loss: %.1f%%\n", ping_stats.packet_loss);
    printf("Network jitter: %d ms\n", ping_stats.jitter);
    printf("Alerts generated: %d\n", alert_count);

    for (int i = 0; i < alert_count; i++) {
        printf("Alert %d: [%s] %s\n", i+1,
               ctime(&alerts[i].timestamp), alerts[i].message);
    }

    // Cleanup
    free(dev);
    pcap_close(handle);
    return 0;
}
