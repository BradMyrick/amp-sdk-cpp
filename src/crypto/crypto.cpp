/**
 * AMP SDK — Crypto implementation.
 * Uses Nayuki's Keccak-256 (MIT, in third_party/nayuki/).
 */

#include "amp/types.hpp"
#include "../../third_party/nayuki/Keccak256.h"

#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <set>

namespace amp::crypto {

std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << "0x";
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::string clean = hex;
    if (clean.substr(0, 2) == "0x") clean = clean.substr(2);
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < clean.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

/// Keccak-256 hash of arbitrary bytes.
std::vector<uint8_t> keccak256(const std::vector<uint8_t>& input) {
    uint8_t hash[Keccak256::HASH_LEN];
    Keccak256::getHash(input.data(), input.size(), hash);
    return std::vector<uint8_t>(hash, hash + Keccak256::HASH_LEN);
}

std::string generateSalt() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    std::vector<uint8_t> bytes(32);
    for (int i = 0; i < 4; i++) {
        uint64_t val = dist(gen);
        std::memcpy(bytes.data() + i * 8, &val, 8);
    }
    return toHex(bytes.data(), bytes.size());
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

std::string computeCommitHash(const std::string& wallet, uint64_t stakeWei, const std::string& salt) {
    // keccak256(address ‖ stake ‖ salt)
    auto addr = fromHex(wallet);

    // Stake as 8-byte big-endian
    uint8_t stakeBytes[8];
    for (int i = 0; i < 8; i++) {
        stakeBytes[7 - i] = static_cast<uint8_t>(stakeWei >> (i * 8));
    }

    // Salt as UTF-8 bytes
    const auto* saltBytes = reinterpret_cast<const uint8_t*>(salt.c_str());

    std::vector<uint8_t> input;
    input.reserve(addr.size() + 8 + salt.size());
    input.insert(input.end(), addr.begin(), addr.end());
    input.insert(input.end(), stakeBytes, stakeBytes + 8);
    input.insert(input.end(), saltBytes, saltBytes + salt.size());

    auto hash = keccak256(input);
    return toHex(hash.data(), hash.size());
}

// ── EIP-712 digest computation ───────────────────────────────

/// Right-aligned 32-byte word from a little-endian value.
std::vector<uint8_t> toWord32(uint64_t value) {
    std::vector<uint8_t> word(32, 0);
    for (int i = 0; i < 8; i++) {
        word[31 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
    return word;
}

/// Left-pad to 32 bytes (for addresses).
std::vector<uint8_t> padLeft32(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> result(32, 0);
    if (input.size() <= 32) {
        std::copy(input.begin(), input.end(), result.end() - input.size());
    }
    return result;
}

/// Right-pad to 32 bytes (for bytes32).
std::vector<uint8_t> padRight32(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> result(32, 0);
    if (input.size() <= 32) {
        std::copy(input.begin(), input.end(), result.begin());
    }
    return result;
}

/// Encode a single field value as a 32-byte word (EIP-712 ABI encoding).
std::vector<uint8_t> encodeFieldValue(const TypedDataField& field, const std::string& value) {
    if (field.type == "string") {
        // keccak256 of the UTF-8 bytes
        auto bytes = std::vector<uint8_t>(value.begin(), value.end());
        return keccak256(bytes);
    }
    if (field.type == "bytes32") {
        return padRight32(fromHex(value));
    }
    if (field.type == "uint256" || field.type == "uint") {
        uint64_t val = 0;
        try { val = std::stoull(value); } catch (...) {}
        return toWord32(val);
    }
    if (field.type == "address") {
        return padLeft32(fromHex(value));
    }
    // Arrays and other types — return zeros for now (ladder arrays handled separately)
    return std::vector<uint8_t>(32, 0);
}

/// Compute keccak256 of a domain separator.
std::vector<uint8_t> computeDomainSeparator(const Eip712TypedData& data) {
    std::string domainTypeStr = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    auto typeHash = keccak256(std::vector<uint8_t>(domainTypeStr.begin(), domainTypeStr.end()));

    auto nameHash = keccak256(std::vector<uint8_t>(data.name.begin(), data.name.end()));
    auto versionHash = keccak256(std::vector<uint8_t>(data.version.begin(), data.version.end()));
    auto chainIdWord = toWord32(data.chain_id);
    auto contractWord = padLeft32(fromHex(data.verifying_contract));

    std::vector<uint8_t> input;
    input.reserve(32 * 5);
    input.insert(input.end(), typeHash.begin(), typeHash.end());
    input.insert(input.end(), nameHash.begin(), nameHash.end());
    input.insert(input.end(), versionHash.begin(), versionHash.end());
    input.insert(input.end(), chainIdWord.begin(), chainIdWord.end());
    input.insert(input.end(), contractWord.begin(), contractWord.end());
    return keccak256(input);
}

/// Compute the struct hash for the primary type.
std::vector<uint8_t> computeStructHash(const Eip712TypedData& data) {
    auto fields = data.types.at(data.primary_type);

    // Build type string: "Type(fieldType fieldName,...)"
    std::string typeString = data.primary_type + "(";
    for (size_t i = 0; i < fields.size(); i++) {
        if (i > 0) typeString += ",";
        typeString += fields[i].type + " " + fields[i].name;
    }
    typeString += ")";

    auto typeHash = keccak256(std::vector<uint8_t>(typeString.begin(), typeString.end()));

    std::vector<uint8_t> input;
    input.reserve(32 * (fields.size() + 1));
    input.insert(input.end(), typeHash.begin(), typeHash.end());

    for (const auto& field : fields) {
        if (field.type == "address[]") {
            // Encode as keccak of concatenated padded addresses
            // Parse comma-separated address list from the message value
            std::string value = "";
            if (data.message.count(field.name)) value = data.message.at(field.name);

            std::vector<uint8_t> concat;
            std::istringstream iss(value);
            std::string addr;
            while (std::getline(iss, addr, ',')) {
                // Trim whitespace
                addr.erase(0, addr.find_first_not_of(" \t"));
                addr.erase(addr.find_last_not_of(" \t") + 1);
                auto padded = padLeft32(fromHex(addr));
                concat.insert(concat.end(), padded.begin(), padded.end());
            }
            auto arrayHash = keccak256(concat);
            input.insert(input.end(), arrayHash.begin(), arrayHash.end());
        } else {
            auto value = data.message.count(field.name) ? data.message.at(field.name) : "";
            auto encoded = encodeFieldValue(field, value);
            input.insert(input.end(), encoded.begin(), encoded.end());
        }
    }

    return keccak256(input);
}

std::vector<uint8_t> computeEip712Digest(const Eip712TypedData& data) {
    auto domainSep = computeDomainSeparator(data);
    auto structHash = computeStructHash(data);

    std::vector<uint8_t> input;
    input.push_back(0x19);
    input.push_back(0x01);
    input.insert(input.end(), domainSep.begin(), domainSep.end());
    input.insert(input.end(), structHash.begin(), structHash.end());
    return keccak256(input);
}

Eip712TypedData buildLadderTypedData(
    uint64_t chainId,
    const std::string& contractAddress,
    const std::string& matchId,
    const std::string& gameId,
    const std::vector<std::string>& rankedPlacements,
    const std::string& transcriptHash,
    uint64_t sessionNonce) {

    // Build the address[] string (comma-separated)
    std::string rankedStr;
    for (size_t i = 0; i < rankedPlacements.size(); i++) {
        if (i > 0) rankedStr += ",";
        rankedStr += rankedPlacements[i];
    }

    Eip712TypedData data;
    data.name = "AMPMultiplayer";
    data.version = "1";
    data.chain_id = chainId;
    data.verifying_contract = contractAddress;
    data.primary_type = "MultiplayerLadder";
    data.types["MultiplayerLadder"] = {
        {"matchId", "bytes32"},
        {"gameId", "bytes32"},
        {"rankedPlacements", "address[]"},
        {"transcriptHash", "bytes32"},
        {"sessionNonce", "uint256"},
    };
    data.message["matchId"] = matchId;
    data.message["gameId"] = gameId;
    data.message["rankedPlacements"] = rankedStr;
    data.message["transcriptHash"] = transcriptHash;
    data.message["sessionNonce"] = std::to_string(sessionNonce);
    return data;
}

} // namespace amp::crypto
