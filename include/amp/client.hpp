/**
 * AMP SDK — REST + WebSocket client.
 *
 * Pure C++17. HTTP via cpp-httplib (header-only), WebSocket via a
 * minimal RFC 6455 implementation. For Unreal Engine games, the
 * AmpUnreal plugin wraps this with UE's native HTTP/WS modules.
 */

#pragma once

#include "amp/types.hpp"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace amp {

// Forward declaration for the WebSocket implementation
class WebSocketImpl;

/// WebSocket client with auto-reconnect.
class AmpWebSocket {
public:
    AmpWebSocket(const std::string& baseUrl, const std::string& token);
    ~AmpWebSocket();

    void connect();
    void close();

    /// Subscribe to an event. Returns an unsubscribe function.
    std::function<void()> on(EventType type, std::function<void(const std::string& json)> handler);

    bool isConnected() const;

private:
    std::unique_ptr<WebSocketImpl> impl_;
};

/// The main AMP client — full API surface.
class AMPClient {
public:
    AMPClient(
        const std::string& serverUrl,
        std::shared_ptr<ISigner> signer = nullptr,
        std::shared_ptr<ICustodialProvider> custodial = nullptr,
        const std::string& playerId = "");
    ~AMPClient();

    // ── Auth ──────────────────────────────────────────

    /// Gasless wallet login — one EIP-191 signature.
    Player login();
    void logout();

    bool authenticated() const { return !token_.empty(); }
    const std::string& wallet() const { return wallet_; }

    // ── Player ────────────────────────────────────────

    std::string me();                                    // JSON string
    std::string getPlayer(const std::string& wallet);   // JSON string

    // ── Games ─────────────────────────────────────────

    std::string games();  // JSON string

    // ── Queue ─────────────────────────────────────────

    std::string joinQueue(const std::string& gameId, const std::string& rulesetId);
    std::string leaveQueue();
    std::string queueStatus();
    std::string playBot();

    // ── Matches (1v1) ────────────────────────────────

    std::string getMatch(const std::string& matchId);
    std::string matchHistory(int limit = 20, int offset = 0);

    /// Report a 1v1 match result. Auto-signs EIP-191.
    std::string reportMatch(
        const std::string& matchId,
        const std::string& result,
        const std::string& transcriptHash = "");

    // ── Parties ───────────────────────────────────────

    std::string createParty(const std::string& gameId, const std::string& rulesetId);
    std::string joinParty(const std::string& inviteCode);
    std::string getParty(const std::string& partyId);
    std::string lockParty(const std::string& partyId);
    std::string disbandParty(const std::string& partyId);

    // ── Multiplayer (N-player) ────────────────────────

    /// Commit to FFA queue. Generates salt internally, returns JSON with salt.
    MultiCommitResult multiCommit(const std::string& gameId, uint64_t stakeWei, int lobbySize);
    std::string multiReveal(const std::string& gameId, const std::string& rulesetId, const std::string& salt);
    std::string getMultiMatch(const std::string& matchId);

    /// Report an N-player ladder. Auto-signs EIP-712.
    std::string multiReport(
        const std::string& matchId,
        const std::vector<std::pair<std::string, int>>& ranked,
        const std::string& transcriptHash,
        uint64_t sessionNonce,
        uint64_t chainId = 43113,
        const std::string& contractAddress = "");

    std::string multiClaim(const std::string& matchId);

    // ── Exit certificates (multiplayer death certs) ────

    /// Submit a death cert on elimination. Auto-signs EIP-191.
    std::string submitExitCert(const std::string& matchId, int rank,
                               uint64_t exitFrame, const std::string& stateHash);

    /// Survivor verifies an eliminated player's exit cert.
    std::string countersignExitCert(const std::string& matchId, const std::string& wallet,
                                    const std::string& stateHash);

    // ── Staked 1v1 escrow ──────────────────────────────

    /// Verify on-chain escrow for a staked 1v1 match (flips to live).
    std::string verifyEscrow(const std::string& matchId);

    // ── Convenience ────────────────────────────────────

    /// One call: queue → wait → matchId. Polls REST every 2s up to
    /// timeoutMs. Returns the matchId; throws Error("timeout") on expiry.
    std::string waitForMatch(int timeoutMs = 30000);

    // ── Events (WebSocket) ────────────────────────────

    AmpWebSocket& events();

    void disconnect();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<AmpWebSocket> ws_;
    std::string server_url_;
    std::string token_;
    std::string wallet_;
    std::shared_ptr<ISigner> signer_;
    std::shared_ptr<ICustodialProvider> custodial_;
    std::string player_id_;
};

} // namespace amp
