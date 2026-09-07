/**
 * AMP SDK — Core types and interfaces.
 *
 * Pure C++ — no engine dependencies. Works with any C++17 compiler.
 * The Unreal Engine plugin wraps these types.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <functional>
#include <memory>
#include <exception>

namespace amp {

// ── Errors ─────────────────────────────────────────────

struct Error : std::exception {
    std::string code;
    std::string message;
    int status = 0;

    Error(std::string c, std::string m, int s = 0)
        : code(std::move(c)), message(std::move(m)), status(s) {}

    const char* what() const noexcept override { return message.c_str(); }
};

// ── EIP-712 typed data ─────────────────────────────────

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

// ── API models ─────────────────────────────────────────

struct Player {
    std::string wallet;
    std::string region;
    std::string language;
};

struct PlayerRating {
    std::string game_id;
    std::string ruleset_id;
    double rating = 0;
    double deviation = 0;
    int wins = 0, losses = 0, draws = 0;
};

struct Ruleset {
    std::string id, name;
    int queue_depth = 0;
};

struct GameInfo {
    std::string id, name;
    std::vector<Ruleset> rulesets;
};

struct MatchFound {
    std::string match_id, game_id;
    bool bot = false;
    struct {
        std::string wallet;
        double rating = 0;
        std::string region;
    } opponent;
    double your_rating = 0;
    std::string expires_at;
};

struct PartyInfo {
    std::string party_id, leader, invite_code, state, game_id, ruleset_id;
    struct Member {
        std::string wallet, region, accepted_at;
    };
    std::vector<Member> members;
};

struct MultiCommitResult {
    bool committed = false;
    int committed_count = 0;
    bool ready = false;
    std::string salt;
};

// ── Signer interfaces ──────────────────────────────────

/**
 * Self-custody signer — the player signs with their own key.
 * Implement with any secp256k1 library (libsecp256k1, OpenSSL, etc.)
 */
struct ISigner {
    virtual ~ISigner() = default;
    virtual std::string getAddress() = 0;
    virtual std::string signPersonalSign(const std::string& message) = 0;
    virtual std::string signTypedData(const Eip712TypedData& data) = 0;
};

/**
 * Custodial provider — the game studio handles fiat ↔ crypto.
 */
struct ICustodialProvider {
    virtual ~ICustodialProvider() = default;
    virtual std::string getAddress(const std::string& playerId) = 0;
    virtual std::string signPersonalSign(const std::string& playerId, const std::string& message) = 0;
    virtual std::string signTypedData(const std::string& playerId, const Eip712TypedData& data) = 0;
};

// ── WebSocket events ───────────────────────────────────

enum class EventType {
    Hello,
    QueueStatus,
    MatchFound,
    MatchResult,
    MatchUpdate,
    MultiLobbyFormed,
    MultiResult,
    MultiCancelled,
};

// ── Crypto helpers (pure, no external deps beyond Nayuki Keccak) ──

namespace crypto {

/// Compute Keccak-256 hash of bytes (32-byte output).
std::vector<uint8_t> keccak256(const std::vector<uint8_t>& input);

/// Convert bytes to 0x-prefixed hex string.
std::string toHex(const uint8_t* data, size_t len);

/// Parse a 0x-prefixed hex string into bytes.
std::vector<uint8_t> fromHex(const std::string& hex);

/// Generate a random 32-byte salt as 0x-prefixed hex.
std::string generateSalt();

/// Build the EIP-191 report message: "AMP_REPORT:v1:{matchId}:{result}"
std::string buildReportMessage(const std::string& matchId, const std::string& result);

/// Build the EIP-191 message for a multiplayer exit certificate (death cert).
/// Must match the amp-server's submit_exit_cert format exactly.
std::string buildExitCertMessage(const std::string& matchId, int rank,
                                 uint64_t exitFrame, const std::string& stateHash);

/// Compute keccak256(address ‖ stake ‖ salt) — commit-reveal hash.
std::string computeCommitHash(const std::string& wallet, uint64_t stakeWei, const std::string& salt);

/// Compute the EIP-712 digest for a MultiplayerLadder signature.
std::vector<uint8_t> computeEip712Digest(const Eip712TypedData& data);

/// Build MultiplayerLadder typed data.
Eip712TypedData buildLadderTypedData(
    uint64_t chainId,
    const std::string& contractAddress,
    const std::string& matchId,
    const std::string& gameId,
    const std::vector<std::string>& rankedPlacements,
    const std::string& transcriptHash,
    uint64_t sessionNonce);

} // namespace crypto

} // namespace amp
