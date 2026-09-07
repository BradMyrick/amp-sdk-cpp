/**
 * AmpCore — engine-free crypto implementation, synced from amp-sdk-cpp
 * (src/crypto/crypto.cpp). No exceptions, no RTTI, no engine types.
 */

#include "AmpCore.h"
#include "Keccak256.h"

#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace ampcore {

using Bytes = std::vector<uint8_t>;

// ── Keccak-256 wrapper ──────────────────────────────────────────

std::vector<uint8_t> keccak256(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> out(32);
    Keccak256::getHash(reinterpret_cast<const uint8_t*>(input.data()),
                   input.size(), out.data());
    return out;
}

// ── Hex helpers ──────────────────────────────────────────────────

static std::string toHexImpl(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2 + 2);
    out += "0x";
    for (size_t i = 0; i < len; i++) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xF];
    }
    return out;
}

std::string toHex(const uint8_t* data, size_t len) { return toHexImpl(data, len); }

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::string h = hex;
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) h = h.substr(2);
    Bytes out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = hexVal(h[i]), lo = hexVal(h[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ── Salt / messages ─────────────────────────────────────────────

std::string generateSalt() {
    std::random_device rd;
    Bytes salt(32);
    for (auto& b : salt) b = static_cast<uint8_t>(rd());
    return toHexImpl(salt.data(), salt.size());
}

std::string buildReportMessage(const std::string& matchId, const std::string& result) {
    return "AMP_REPORT:v1:" + matchId + ":" + result;
}

std::string buildExitCertMessage(const std::string& matchId, int rank,
                                 uint64_t exitFrame, const std::string& stateHash) {
    return "AMP exit certificate\n\n"
           "Match: " + matchId + "\n"
           "Rank: " + std::to_string(rank) + "\n"
           "Exit frame: " + std::to_string(exitFrame) + "\n"
           "State hash: " + stateHash + "\n\n"
           "This signature is free. It certifies your elimination and unlocks your reporting bond.";
}

std::vector<uint8_t> eip191Digest(const std::string& message) {
    std::string prefixed = std::string("\x19", 1) +
                           "Ethereum Signed Message:\n" +
                           std::to_string(message.size()) + message;
    return keccak256({prefixed.begin(), prefixed.end()});
}

// ── Commit hash ─────────────────────────────────────────────────

std::string computeCommitHash(const std::string& wallet, uint64_t stakeWei,
                              const std::string& salt) {
    Bytes addr = fromHex(wallet);
    if (addr.size() > 20) addr.resize(20);

    Bytes input;
    input.reserve(20 + 8 + salt.size());
    input.insert(input.end(), addr.begin(), addr.end());
    for (int i = 7; i >= 0; i--)
        input.push_back(static_cast<uint8_t>((stakeWei >> (i * 8)) & 0xFF));
    input.insert(input.end(), salt.begin(), salt.end());

    auto hash = keccak256(input);
    return toHexImpl(hash.data(), hash.size());
}

// ── EIP-712 ─────────────────────────────────────────────────────

static Bytes toWord32(uint64_t value) {
    Bytes out(32, 0);
    for (int i = 0; i < 8; i++)
        out[31 - i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    return out;
}

static Bytes padLeft32(const Bytes& in) {
    Bytes out(32, 0);
    if (in.size() <= 32)
        for (size_t i = 0; i < in.size(); i++) out[32 - in.size() + i] = in[i];
    return out;
}

static Bytes padRight32(const Bytes& in) {
    Bytes out(32, 0);
    for (size_t i = 0; i < in.size() && i < 32; i++) out[i] = in[i];
    return out;
}

/// No-throw uint64 parse (UE builds with -fno-exceptions).
static uint64_t parseUint64(const std::string& value, uint64_t fallback = 0) {
    uint64_t acc = 0;
    if (value.empty()) return fallback;
    for (char c : value) {
        if (c < '0' || c > '9') return fallback;
        if (acc > (UINT64_MAX - (c - '0')) / 10) return fallback;
        acc = acc * 10 + static_cast<uint64_t>(c - '0');
    }
    return acc;
}

static Bytes encodeFieldValue(const TypedDataField& field, const std::string& value) {
    if (field.type == "string") {
        return keccak256({value.begin(), value.end()});
    }
    if (field.type == "bytes32") {
        return padRight32(fromHex(value));
    }
    if (field.type == "uint256" || field.type == "uint") {
        return toWord32(parseUint64(value));
    }
    if (field.type == "address") {
        return padLeft32(fromHex(value));
    }
    return Bytes(32, 0);
}

static std::vector<uint8_t> computeDomainSeparator(const Eip712TypedData& data) {
    std::string domainTypeStr =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    auto typeHash = keccak256({domainTypeStr.begin(), domainTypeStr.end()});

    Bytes enc;
    auto nameHash = keccak256({data.name.begin(), data.name.end()});
    auto versionHash = keccak256({data.version.begin(), data.version.end()});
    enc.insert(enc.end(), nameHash.begin(), nameHash.end());
    enc.insert(enc.end(), versionHash.begin(), versionHash.end());
    Bytes chain = toWord32(data.chain_id);
    enc.insert(enc.end(), chain.begin(), chain.end());
    Bytes addr = padLeft32(fromHex(data.verifying_contract));
    enc.insert(enc.end(), addr.begin(), addr.end());

    Bytes withType(typeHash);
    withType.insert(withType.end(), enc.begin(), enc.end());
    auto sep = keccak256(withType);
    return sep;
}

static std::vector<uint8_t> computeStructHash(const Eip712TypedData& data,
                                              const std::string& structName,
                                              const std::map<std::string, std::string>& message) {
    // Encode the type string (this struct's fields + dependencies, alphabetical)
    const std::vector<TypedDataField>& fields = data.types.at(structName);
    std::string typeString = structName + "(";
    for (size_t i = 0; i < fields.size(); i++) {
        if (i) typeString += ",";
        typeString += fields[i].type + " " + fields[i].name;
    }
    typeString += ")";

    auto typeHash = keccak256({typeString.begin(), typeString.end()});

    Bytes enc = typeHash;
    for (const auto& field : fields) {
        if (field.type == "address[]") {
            // keccak256(abi.encodePacked(keccak256(abi.encode(addresses))))
            Bytes addrPacked;
            for (const auto& [key, val] : message) {
                (void)key;
                if (val.size() == 42) { // an address
                    Bytes a = padLeft32(fromHex(val));
                    addrPacked.insert(addrPacked.end(), a.begin(), a.end());
                }
            }
            auto inner = keccak256(addrPacked);
            enc.insert(enc.end(), inner.begin(), inner.end());
        } else {
            auto it = message.find(field.name);
            std::string val = (it != message.end()) ? it->second : "";
            Bytes encField = encodeFieldValue(field, val);
            enc.insert(enc.end(), encField.begin(), encField.end());
        }
    }
    return keccak256(enc);
}

std::vector<uint8_t> computeEip712Digest(const Eip712TypedData& data) {
    auto domainSep = computeDomainSeparator(data);
    auto structHash = computeStructHash(data, data.primary_type, data.message);

    Bytes payload;
    payload.push_back(0x19);
    payload.push_back(0x01);
    payload.insert(payload.end(), domainSep.begin(), domainSep.end());
    payload.insert(payload.end(), structHash.begin(), structHash.end());
    return keccak256(payload);
}

Eip712TypedData buildLadderTypedData(
    uint64_t chainId,
    const std::string& contractAddress,
    const std::string& matchId,
    const std::string& gameId,
    const std::vector<std::string>& rankedPlacements,
    const std::string& transcriptHash,
    uint64_t sessionNonce) {
    Eip712TypedData td;
    td.name = "AMPMultiplayer";
    td.version = "1";
    td.chain_id = chainId;
    td.verifying_contract = contractAddress;
    td.primary_type = "MultiplayerLadder";

    td.types["MultiplayerLadder"] = {
        {"matchId", "bytes32"},
        {"gameId", "bytes32"},
        {"rankedPlacements", "address[]"},
        {"transcriptHash", "bytes32"},
        {"sessionNonce", "uint256"},
    };

    td.message["matchId"] = matchId;
    td.message["gameId"] = gameId;
    for (size_t i = 0; i < rankedPlacements.size(); i++)
        td.message["placement" + std::to_string(i)] = rankedPlacements[i];
    td.message["transcriptHash"] = transcriptHash;
    td.message["sessionNonce"] = std::to_string(sessionNonce);

    return td;
}

} // namespace ampcore
