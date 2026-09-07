/**
 * AMP SDK — HTTP client implementation (POSIX + OpenSSL TLS).
 * Minimal: exactly enough for the AMP REST API.
 */

#include "amp/http_client.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <cctype>

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace amp::http {

struct UrlParts {
    std::string scheme, host, path;
    int port = 80;
    bool tls = false;
};

static UrlParts parseUrl(const std::string& url) {
    UrlParts p;
    std::string rest = url;

    if (rest.rfind("https://", 0) == 0) {
        p.scheme = "https"; p.tls = true; p.port = 443;
        rest = rest.substr(8);
    } else if (rest.rfind("http://", 0) == 0) {
        p.scheme = "http"; p.tls = false; p.port = 80;
        rest = rest.substr(7);
    }

    auto slash = rest.find('/');
    if (slash == std::string::npos) {
        p.host = rest;
        p.path = "/";
    } else {
        p.host = rest.substr(0, slash);
        p.path = rest.substr(slash);
    }

    auto colon = p.host.find(':');
    if (colon != std::string::npos) {
        try { p.port = std::stoi(p.host.substr(colon + 1)); } catch (...) {}
        p.host = p.host.substr(0, colon);
    }

    return p;
}

struct TlsGlobals {
    SSL_CTX* ctx = nullptr;
    TlsGlobals() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
            // Verify server certificates against the system trust store;
            // fail closed on any verification problem.
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
            SSL_CTX_set_default_verify_paths(ctx);
        }
    }
    ~TlsGlobals() {
        if (ctx) SSL_CTX_free(ctx);
    }
};

static SSL_CTX* sharedTlsCtx() {
    static TlsGlobals g;
    return g.ctx;
}

struct Connection {
    int fd = -1;
    SSL* ssl = nullptr;

    ~Connection() { close(); }
    void close() {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (fd >= 0) { ::close(fd); fd = -1; }
    }

    bool connect(const std::string& host, int port, bool tls) {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
            return false;

        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) { freeaddrinfo(res); return false; }

        struct timeval tv{10, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        bool ok = ::connect(fd, res->ai_addr, res->ai_addrlen) == 0;
        freeaddrinfo(res);
        if (!ok) { close(); return false; }

        if (tls) {
            SSL_CTX* ctx = sharedTlsCtx();
            if (!ctx) { close(); return false; }
            ssl = SSL_new(ctx);
            if (!ssl) { close(); return false; }
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, host.c_str());
            // Pin the certificate to the hostname we dialed
            SSL_set1_host(ssl, host.c_str());
            if (SSL_connect(ssl) != 1) { close(); return false; }
            if (SSL_get_verify_result(ssl) != X509_V_OK) { close(); return false; }
        }
        return true;
    }

    bool write(const std::string& data) {
        size_t total = 0;
        while (total < data.size()) {
            int n;
            if (ssl) n = SSL_write(ssl, data.c_str() + total, static_cast<int>(data.size() - total));
            else n = static_cast<int>(::send(fd, data.c_str() + total, data.size() - total, 0));
            if (n <= 0) return false;
            total += static_cast<size_t>(n);
        }
        return true;
    }

    std::string readAll() {
        std::string result;
        char buf[8192];
        while (true) {
            int n;
            if (ssl) n = SSL_read(ssl, buf, sizeof(buf));
            else n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
            if (n <= 0) break;
            result.append(buf, static_cast<size_t>(n));
        }
        return result;
    }
};

// ── Public API ─────────────────────────────────────────────────

class HttpClient::Impl {
public:
    std::string baseUrl;
    std::string bearerToken;
    int timeout;

    Response doRequest(const std::string& method, const std::string& path, const std::string& body) {
        auto parts = parseUrl(baseUrl + path);

        Connection conn;
        if (!conn.connect(parts.host, parts.port, parts.tls)) {
            return {0, "{\"error\":\"network\",\"message\":\"Cannot reach the matchmaker at " + baseUrl + "\"}"};
        }

        std::ostringstream req;
        req << method << " " << parts.path << " HTTP/1.1\r\n";
        req << "Host: " << parts.host << "\r\n";
        req << "Content-Type: application/json\r\n";
        if (!bearerToken.empty())
            req << "Authorization: Bearer " << bearerToken << "\r\n";
        req << "Content-Length: " << body.size() << "\r\n";
        req << "Connection: close\r\n\r\n";
        req << body;

        if (!conn.write(req.str()))
            return {0, "{\"error\":\"network\",\"message\":\"Failed to send request\"}"};

        std::string raw = conn.readAll();

        Response resp;
        // Parse status line: "HTTP/1.1 200 OK"
        auto sp1 = raw.find(' ');
        if (sp1 != std::string::npos) {
            try { resp.status = std::stoi(raw.substr(sp1 + 1, 3)); } catch (...) {}
        }

        // Split headers from body
        auto headerEnd = raw.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            std::string bodyRaw = raw.substr(headerEnd + 4);

            // Handle chunked encoding
            if (raw.find("Transfer-Encoding: chunked") != std::string::npos ||
                raw.find("transfer-encoding: chunked") != std::string::npos) {
                std::string dechunked;
                size_t pos = 0;
                while (pos < bodyRaw.size()) {
                    auto lineEnd = bodyRaw.find("\r\n", pos);
                    if (lineEnd == std::string::npos) break;
                    size_t chunkSize = 0;
                    try { chunkSize = std::stoull(bodyRaw.substr(pos, lineEnd - pos), nullptr, 16); } catch (...) { break; }
                    if (chunkSize == 0) break;
                    dechunked += bodyRaw.substr(lineEnd + 2, chunkSize);
                    pos = lineEnd + 2 + chunkSize + 2;
                }
                resp.body = dechunked;
            } else {
                resp.body = bodyRaw;
            }
        }

        return resp;
    }
};

HttpClient::HttpClient(const std::string& baseUrl, int timeout)
    : impl_(std::make_unique<Impl>()) {
    std::string url = baseUrl;
    if (!url.empty() && url.back() == '/') url.pop_back();
    impl_->baseUrl = url;
    impl_->timeout = timeout;
}

HttpClient::~HttpClient() = default;

void HttpClient::setBearerToken(const std::string& token) { impl_->bearerToken = token; }
void HttpClient::clearToken() { impl_->bearerToken.clear(); }

Response HttpClient::get(const std::string& path) { return impl_->doRequest("GET", path, ""); }
Response HttpClient::post(const std::string& path, const std::string& jsonBody) { return impl_->doRequest("POST", path, jsonBody); }
Response HttpClient::del(const std::string& path) { return impl_->doRequest("DELETE", path, ""); }

} // namespace amp::http
