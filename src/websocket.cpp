/**
 * AMP SDK — Minimal RFC 6455 WebSocket client (POSIX + OpenSSL TLS).
 *
 * Supports exactly what the AMP event stream needs:
 *   - wss:// with SNI, text frames, ping/pong, auto-reconnect
 *   - JSON messages of the form {"type":"...","data":{...}}
 */

#include "amp/client.hpp"
#include "amp/http_client.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <strings.h>
#include <cerrno>
#include <sstream>
#include <random>
#include <algorithm>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace amp {

// ── Base64 for the WebSocket handshake key ─────────────────────

static std::string base64Encode(const uint8_t* data, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];
        out += table[(n >> 18) & 63];
        out += table[(n >> 12) & 63];
        out += (i + 1 < len) ? table[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? table[n & 63] : '=';
    }
    return out;
}

// ── Event-type mapping ─────────────────────────────────────────

static std::string eventTypeName(EventType t) {
    switch (t) {
        case EventType::Hello: return "hello";
        case EventType::QueueStatus: return "queue_status";
        case EventType::MatchFound: return "match_found";
        case EventType::MatchResult: return "match_result";
        case EventType::MatchUpdate: return "match_update";
        case EventType::MultiLobbyFormed: return "multi_lobby_formed";
        case EventType::MultiResult: return "multi_result";
        case EventType::MultiCancelled: return "multi_cancelled";
    }
    return "";
}

// ── Connection (shared transport with http_client) ─────────────

namespace {

struct UrlParts {
    std::string host, path;
    int port = 443;
    bool tls = true;
};

UrlParts parseWsUrl(const std::string& url) {
    UrlParts p;
    std::string rest = url;
    if (rest.rfind("wss://", 0) == 0) { p.tls = true; p.port = 443; rest = rest.substr(6); }
    else if (rest.rfind("ws://", 0) == 0) { p.tls = false; p.port = 80; rest = rest.substr(5); }
    else if (rest.rfind("https://", 0) == 0) { p.tls = true; p.port = 443; rest = rest.substr(8); }
    else if (rest.rfind("http://", 0) == 0) { p.tls = false; p.port = 80; rest = rest.substr(7); }

    auto slash = rest.find('/');
    if (slash == std::string::npos) { p.host = rest; p.path = "/"; }
    else { p.host = rest.substr(0, slash); p.path = rest.substr(slash); }

    auto colon = p.host.find(':');
    if (colon != std::string::npos) {
        try { p.port = std::stoi(p.host.substr(colon + 1)); } catch (...) {}
        p.host = p.host.substr(0, colon);
    }
    return p;
}

} // namespace

// RFC 6455 §4.2.2: Sec-WebSocket-Accept == base64(SHA1(key + GUID))
static bool validateAcceptKey(const std::string& headers, const std::string& key) {
    static const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    // Case-insensitive: RFC says Sec-WebSocket-Accept, tungstenite sends
    // Sec-Websocket-Accept, proxies may lowercase entirely.
    size_t pos = std::string::npos;
    {
        const char* needle = "ec-websocket-accept:";
        const size_t n = strlen(needle);
        for (size_t i = 0; i + n <= headers.size(); i++) {
            if (strncasecmp(headers.data() + i, needle, n) == 0) { pos = i; break; }
        }
    }
    if (pos == std::string::npos) return false;
    pos = headers.find(':', pos);
    auto eol = headers.find("\r\n", pos);
    if (eol == std::string::npos) return false;
    auto vstart = headers.find_first_not_of(" \t", pos + 1);
    if (vstart == std::string::npos || vstart >= eol) return false;
    std::string accept = headers.substr(vstart, eol - vstart);

    uint8_t sha[SHA_DIGEST_LENGTH];
    std::string cat = key + GUID;
    SHA1(reinterpret_cast<const uint8_t*>(cat.data()), cat.size(), sha);

    std::string out(64, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), sha, SHA_DIGEST_LENGTH);
    // Keep base64 padding — servers send it (RFC 6455 examples included).
    std::string expected;
    for (char c : out) {
        if (c == '\0') break;
        expected += c;
    }

    return expected == accept;
}

// ── WebSocketImpl ──────────────────────────────────────────────

class WebSocketImpl {
public:
    using Handler = std::function<void(const std::string&)>;

    WebSocketImpl(std::string url, std::string token)
        : url_(std::move(url)), token_(std::move(token)) {}

    ~WebSocketImpl() { stop(); }

    void start() {
        running_ = true;
        thread_ = std::thread([this] { runLoop(); });
    }

    void stop() {
        running_ = false;
        // Reader exits within one SO_RCVTIMEO window (250 ms);
        // only then is it safe to free the SSL/fd it was using.
        if (thread_.joinable()) thread_.join();
        closeSocket();
    }

    void on(const std::string& type, Handler h) {
        std::lock_guard<std::mutex> lock(handlersMutex_);
        handlers_[type] = std::move(h);
    }

    bool connected() const { return connected_; }

private:
    std::string url_, token_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::thread thread_;
    std::mutex handlersMutex_;
    std::map<std::string, Handler> handlers_;

    int fd_ = -1;
    SSL* ssl_ = nullptr;

    void closeSocket() {
        if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        connected_ = false;
    }

    bool tcpConnect(const std::string& host, int port, bool tls) {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
            return false;

        fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd_ < 0) { freeaddrinfo(res); return false; }

        // Generous timeout for TCP + TLS handshake (tunnel RTTs)
        struct timeval tv{10, 0};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        bool ok = ::connect(fd_, res->ai_addr, res->ai_addrlen) == 0;
        freeaddrinfo(res);
        if (!ok) { closeSocket(); return false; }

        if (tls) {
            SSL_CTX* ctx = sharedCtx();
            if (!ctx) { closeSocket(); return false; }
            ssl_ = SSL_new(ctx);
            SSL_set_fd(ssl_, fd_);
            SSL_set_tlsext_host_name(ssl_, host.c_str());
            SSL_set1_host(ssl_, host.c_str());
            if (SSL_connect(ssl_) != 1) { closeSocket(); return false; }
            if (SSL_get_verify_result(ssl_) != X509_V_OK) { closeSocket(); return false; }
        }

        // After handshake: short receive timeout so the read loop
        // wakes up regularly to notice stop().
        struct timeval fast{0, 250 * 1000};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &fast, sizeof(fast));
        return true;
    }

    static SSL_CTX* sharedCtx() {
        static SSL_CTX* ctx = [] {
            SSL_CTX* c = SSL_CTX_new(TLS_client_method());
            if (c) {
                SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
                SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
                SSL_CTX_set_default_verify_paths(c);
            }
            return c;
        }();
        return ctx;
    }

    bool sendRaw(const uint8_t* data, size_t len) {
        size_t total = 0;
        while (total < len) {
            int n = ssl_
                ? SSL_write(ssl_, data + total, static_cast<int>(len - total))
                : static_cast<int>(::send(fd_, data + total, len - total, 0));
            if (n <= 0) return false;
            total += static_cast<size_t>(n);
        }
        return true;
    }

    /// Blocking read that survives SO_RCVTIMEO wakeups and stop() requests.
    /// Returns true when all bytes were read; false on error or stop().
    bool recvRaw(uint8_t* buf, size_t len) {
        size_t total = 0;
        while (total < len) {
            if (!running_.load()) return false;
            int n = ssl_
                ? SSL_read(ssl_, buf + total, static_cast<int>(len - total))
                : static_cast<int>(::recv(fd_, buf + total, len - total, 0));
            if (n > 0) {
                total += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) return false; // peer closed

            if (ssl_) {
                int sslErr = SSL_get_error(ssl_, n);
                // Timeout (EAGAIN) surfaces as WANT_READ or SYSCALL+EAGAIN
                if (sslErr == SSL_ERROR_WANT_READ ||
                    (sslErr == SSL_ERROR_SYSCALL &&
                     (errno == EAGAIN || errno == EWOULDBLOCK)))
                    continue;
                return false;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return false;
        }
        return true;
    }

    bool sendFrame(uint8_t opcode, const std::string& payload) {
        std::vector<uint8_t> frame;
        frame.push_back(0x80 | opcode); // FIN + opcode

        // Client frames must be masked
        if (payload.size() < 126) {
            frame.push_back(0x80 | static_cast<uint8_t>(payload.size()));
        } else if (payload.size() <= 0xFFFF) {
            frame.push_back(0x80 | 126);
            frame.push_back(static_cast<uint8_t>(payload.size() >> 8));
            frame.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
        } else {
            frame.push_back(0x80 | 127);
            uint64_t len = payload.size();
            for (int i = 7; i >= 0; i--)
                frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }

        uint8_t mask[4];
        {
            std::random_device rd;
            for (auto& m : mask) m = static_cast<uint8_t>(rd());
        }
        frame.insert(frame.end(), mask, mask + 4);

        for (size_t i = 0; i < payload.size(); i++)
            frame.push_back(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);

        return sendRaw(frame.data(), frame.size());
    }

    void runLoop() {
        // Auto-reconnect: drops are retried with capped backoff until the
        // user calls close(). A fresh handshake re-authenticates the token.
        int backoffMs = 1000;
        while (running_.load()) {
            if (runOnce()) {
                backoffMs = 1000; // clean session — reset backoff
            }
            if (!running_.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
            backoffMs = std::min(backoffMs * 2, 15000);
        }
        connected_ = false;
    }

    /// One connection attempt + pump. Returns true when the session ran
    /// cleanly (handshake completed), false when it never connected.
    bool runOnce() {
        auto parts = parseWsUrl(url_);
        std::string path = parts.path;
        if (path.find('?') == std::string::npos)
            path += "?token=" + token_;
        else
            path += "&token=" + token_;

        if (!tcpConnect(parts.host, parts.port, parts.tls)) return false;

        // Handshake
        std::random_device rd;
        uint8_t raw[16];
        for (auto& b : raw) b = static_cast<uint8_t>(rd());
        std::string key = base64Encode(raw, sizeof(raw));

        std::ostringstream req;
        req << "GET " << path << " HTTP/1.1\r\n";
        req << "Host: " << parts.host << "\r\n";
        req << "Upgrade: websocket\r\n";
        req << "Connection: Upgrade\r\n";
        req << "Sec-WebSocket-Key: " << key << "\r\n";
        req << "Sec-WebSocket-Version: 13\r\n";
        req << "Origin: https://" << parts.host << "\r\n";
        req << "\r\n";

        if (!sendRaw(reinterpret_cast<const uint8_t*>(req.str().c_str()), req.str().size()))
            return false;

        // Read until end of headers (timeout-tolerant via recvRaw)
        std::string headers;
        bool handshakeOk = false;
        while (running_) {
            char c;
            if (!recvRaw(reinterpret_cast<uint8_t*>(&c), 1)) break;
            headers += c;
            if (headers.size() >= 4 &&
                headers.compare(headers.size() - 4, 4, "\r\n\r\n") == 0) {
                handshakeOk =
                    headers.find(" 101 ") != std::string::npos &&
                    validateAcceptKey(headers, key);
                break;
            }
        }
        if (!handshakeOk) return false;

        connected_ = true;

        // Frame loop
        while (running_) {
            uint8_t hdr[2];
            if (!recvRaw(hdr, 2)) break;

            bool fin = (hdr[0] & 0x80) != 0;
            (void)fin;
            uint8_t opcode = hdr[0] & 0x0F;
            bool masked = (hdr[1] & 0x80) != 0;
            uint64_t len = hdr[1] & 0x7F;

            if (len == 126) {
                uint8_t ext[2];
                if (!recvRaw(ext, 2)) break;
                len = (static_cast<uint64_t>(ext[0]) << 8) | ext[1];
            } else if (len == 127) {
                uint8_t ext[8];
                if (!recvRaw(ext, 8)) break;
                len = 0;
                for (auto b : ext) len = (len << 8) | b;
            }
            if (len > 16 * 1024 * 1024) break; // sanity cap

            uint8_t mask[4] = {0};
            if (masked && !recvRaw(mask, 4)) break;

            std::string payload(len, '\0');
            if (len > 0 && !recvRaw(reinterpret_cast<uint8_t*>(payload.data()), len)) break;
            if (masked)
                for (uint64_t i = 0; i < len; i++)
                    payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);

            switch (opcode) {
                case 0x1: { // text
                    dispatch(payload);
                    break;
                }
                case 0x9: // ping → pong
                    sendFrame(0xA, payload);
                    break;
                case 0xA: // pong
                    break;
                case 0x8: // close
                    sendFrame(0x8, "");
                    break;
                default:
                    break;
            }
        }
        return true; // a real session ran; reconnect if still running
    }

    void dispatch(const std::string& json) {
        // {"type":"...","data":{...}} → hand the full JSON to the handler
        auto typeStart = json.find("\"type\"");
        if (typeStart == std::string::npos) return;
        auto colon = json.find(':', typeStart);
        if (colon == std::string::npos) return;
        auto q1 = json.find('"', colon);
        if (q1 == std::string::npos) return;
        auto q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return;
        std::string type = json.substr(q1 + 1, q2 - q1 - 1);

        Handler h;
        {
            std::lock_guard<std::mutex> lock(handlersMutex_);
            auto it = handlers_.find(type);
            if (it != handlers_.end()) h = it->second;
        }
        if (h) h(json);
    }
};

// ── AmpWebSocket public API ────────────────────────────────────

AmpWebSocket::AmpWebSocket(const std::string& baseUrl, const std::string& token) {
    // https://host → wss://host/v1/ws
    std::string wsUrl = baseUrl;
    if (wsUrl.rfind("https://", 0) == 0) wsUrl = "wss://" + wsUrl.substr(8);
    else if (wsUrl.rfind("http://", 0) == 0) wsUrl = "ws://" + wsUrl.substr(7);
    if (!wsUrl.empty() && wsUrl.back() == '/') wsUrl.pop_back();
    wsUrl += "/v1/ws";

    impl_ = std::make_unique<WebSocketImpl>(wsUrl, token);
}

AmpWebSocket::~AmpWebSocket() = default;

void AmpWebSocket::connect() { impl_->start(); }
void AmpWebSocket::close() { impl_->stop(); }
bool AmpWebSocket::isConnected() const { return impl_->connected(); }

std::function<void()> AmpWebSocket::on(EventType type,
                                        std::function<void(const std::string& json)> handler) {
    std::string name = eventTypeName(type);
    impl_->on(name, std::move(handler));
    return [this, name]() { impl_->on(name, nullptr); };
}

} // namespace amp
