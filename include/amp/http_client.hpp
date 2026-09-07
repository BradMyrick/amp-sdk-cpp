/**
 * AMP SDK — Minimal HTTP client (POSIX sockets + OpenSSL TLS).
 *
 * Supports the exact subset needed by the AMP REST API:
 *   GET, POST, DELETE with JSON bodies and Bearer auth.
 */

#pragma once

#include <string>
#include <map>
#include <memory>

namespace amp::http {

struct Response {
    int status = 0;
    std::string body;
};

class HttpClient {
public:
    explicit HttpClient(const std::string& baseUrl, int timeoutSeconds = 10);
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    void setBearerToken(const std::string& token);
    void clearToken();

    Response get(const std::string& path);
    Response post(const std::string& path, const std::string& jsonBody = "");
    Response del(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace amp::http
