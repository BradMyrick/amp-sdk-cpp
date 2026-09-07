/**
 * AmpCore — the AMP protocol core, vendored from amp-sdk-cpp.
 *
 * ENGINE-FREE and EXCEPTION-FREE: compiled inside the Unreal module under
 * -fno-exceptions -fno-rtti. Validated against the cross-SDK golden
 * vectors shared by the TS / C# / C++ / Rust SDKs and amp-server.
 *
 * Do NOT add engine types or throwing code to this directory.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace ampcore {

// ── EIP-712 typed data ─────────────────────────────────────────

struct TypedDataField {
    std::string name;
    std::string type;
};

struct Eip712TypedData {
    std::string name;             // domain name
    std::string version;          // domain version
    uint64_t chain_id = 0;
    std::string verifying_contract;
    std::string primary_type;
    std::map<std::string, std::vector<TypedDataField>> types;
    std::map<std::string, std::string> message;  // field name → string value
};

// ── Crypto helpers ──────────────────────────────────────────────

/// Compute Keccak-256 hash of bytes (32-byte output).
std::vector<uint8_t> keccak256(const std::vector<uint8_t>& input);

/// Convert bytes to 0x-prefixed lowercase hex.
std::string toHex(const uint8_t* data, size_t len);

/// Parse a 0x-prefixed hex string into bytes.
std::vector<uint8_t> fromHex(const std::string& hex);

/// Generate a random 32-byte salt as 0x-prefixed hex (OS entropy).
std::string generateSalt();

/// EIP-191 report message: "AMP_REPORT:v1:{matchId}:{result}"
std::string buildReportMessage(const std::string& matchId, const std::string& result);

/// EIP-191 exit-certificate (death cert) message — must match amp-server exactly.
std::string buildExitCertMessage(const std::string& matchId, int rank,
                                 uint64_t exitFrame, const std::string& stateHash);

/// Commit-reveal hash: keccak256(addr20 ‖ stake_u64_be(8) ‖ salt-utf8).
/// Golden vector (cross-SDK):
///   wallet  0x95CC495dF579981d3Ffa4a8f77B93A17563E077a
///   stake   1000000000000000
///   salt    "0xdeadbeef"
///   → 0x2d5491f1ad0117eea0c302b3cfb07590fef2d3892349e017361afd1bb5e5be10
std::string computeCommitHash(const std::string& wallet, uint64_t stakeWei,
                              const std::string& salt);

/// EIP-712 digest (domain separator ‖ hashStruct) for signing.
std::vector<uint8_t> computeEip712Digest(const Eip712TypedData& data);

/// Build the MultiplayerLadder typed data for N-player reports.
Eip712TypedData buildLadderTypedData(
    uint64_t chainId,
    const std::string& contractAddress,
    const std::string& matchId,
    const std::string& gameId,
    const std::vector<std::string>& rankedPlacements,
    const std::string& transcriptHash,
    uint64_t sessionNonce);

/// EIP-191 personal-message digest:
/// keccak256("\x19Ethereum Signed Message:\n" + len + message)
std::vector<uint8_t> eip191Digest(const std::string& message);

} // namespace ampcore
