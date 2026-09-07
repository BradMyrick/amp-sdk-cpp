/**
 * AMP SDK — Minimal JSON helpers (internal).
 *
 * Just enough to build request bodies and extract top-level fields from
 * responses without pulling in a full JSON library. All client methods
 * that return `std::string` hand the raw JSON to the caller.
 */

#pragma once

#include <string>
#include <vector>
#include <utility>
#include <optional>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace amp::json {

/// JSON-escape a string value.
inline std::string escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setfill('0') << std::setw(4)
                        << static_cast<int>(static_cast<unsigned char>(c));
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

/// Build a flat JSON object from key/value pairs. Null/false omits the field.
inline std::string build(const std::vector<std::pair<std::string, std::optional<std::string>>>& fields) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& [k, v] : fields) {
        if (!v.has_value()) continue;
        if (!first) oss << ",";
        oss << "\"" << escape(k) << "\":\"" << escape(*v) << "\"";
        first = false;
    }
    oss << "}";
    return oss.str();
}

/// Extract a top-level string field: `"field":"value"` → value (unescaped).
inline std::optional<std::string> getString(const std::string& json, const std::string& field) {
    std::string needle = "\"" + field + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return std::nullopt;

    auto colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return std::nullopt;

    auto p = colon + 1;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) p++;

    if (p >= json.size() || json[p] != '"') return std::nullopt;
    p++;
    std::string out;
    while (p < json.size() && json[p] != '"') {
        if (json[p] == '\\' && p + 1 < json.size()) {
            p++;
            switch (json[p]) {
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    if (p + 4 < json.size()) {
                        try {
                            out += static_cast<char>(std::stoi(json.substr(p + 1, 4), nullptr, 16));
                        } catch (...) {}
                        p += 4;
                    }
                    break;
                }
                default: out += json[p];
            }
        } else {
            out += json[p];
        }
        p++;
    }
    return out;
}

/// Extract a top-level numeric field (integer only).
inline std::optional<int64_t> getInt(const std::string& json, const std::string& field) {
    std::string needle = "\"" + field + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    auto colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return std::nullopt;
    auto p = colon + 1;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) p++;
    auto start = p;
    while (p < json.size() && (isdigit(static_cast<unsigned char>(json[p])) || json[p] == '-')) p++;
    if (p == start) return std::nullopt;
    try {
        return std::stoll(json.substr(start, p - start));
    } catch (...) {
        return std::nullopt;
    }
}

/// Extract a top-level boolean field.
inline std::optional<bool> getBool(const std::string& json, const std::string& field) {
    std::string needle = "\"" + field + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    auto colon = json.find(':', pos + needle.size());
    if (colon == std::string::npos) return std::nullopt;
    auto p = json.find_first_not_of(" \t", colon + 1);
    if (p == std::string::npos) return std::nullopt;
    if (json.compare(p, 4, "true") == 0) return true;
    if (json.compare(p, 5, "false") == 0) return false;
    return std::nullopt;
}

} // namespace amp::json
