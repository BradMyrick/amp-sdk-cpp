/**
 * AMP SDK — client implementation.
 *
 * Wires the HTTP client, signer, and crypto helpers into the full
 * AMP API surface. All endpoints match the production server routes:
 *   /v1/auth, /v1/games, /v1/queue, /v1/matches, /v1/parties, /v1/multi
 */

#include "amp/client.hpp"
#include "amp/http_client.hpp"
#include "json.hpp"

#include <stdexcept>
#include <cctype>
#include <sstream>

namespace amp {

// ── Impl ───────────────────────────────────────────────────────

class AMPClient::Impl {
public:
    http::HttpClient rest;

    explicit Impl(const std::string& serverUrl) : rest(serverUrl) {}
};

// ── Lifecycle ──────────────────────────────────────────────────

AMPClient::AMPClient(const std::string& serverUrl,
                     std::shared_ptr<ISigner> signer,
                     std::shared_ptr<ICustodialProvider> custodial,
                     const std::string& playerId)
    : impl_(std::make_unique<Impl>(serverUrl)),
      server_url_(serverUrl),
      signer_(std::move(signer)),
      custodial_(std::move(custodial)),
      player_id_(playerId) {}

AMPClient::~AMPClient() { disconnect(); }

// ── Helpers ────────────────────────────────────────────────────

namespace {

std::string requireOk(const http::Response& resp, const char* what) {
    if (resp.status == 0)
        throw Error("network", resp.body.empty() ? std::string("Network error: ") + what : resp.body);
    if (resp.status >= 400) {
        auto msg = json::getString(resp.body, "error");
        auto code = json::getString(resp.body, "code");
        throw Error(code.value_or("http_error"),
                    msg.value_or("HTTP " + std::to_string(resp.status) + " at " + what),
                    resp.status);
    }
    return resp.body;
}

} // namespace

// ── Auth ───────────────────────────────────────────────────────

Player AMPClient::login() {
    if (!signer_ && !custodial_)
        throw Error("no_signer", "No signer or custodial provider configured");

    wallet_ = signer_ ? signer_->getAddress() : custodial_->getAddress(player_id_);

    // 1. Challenge
    auto challengeBody = requireOk(
        impl_->rest.post("/v1/auth/challenge", json::build({{"wallet", wallet_}})),
        "auth/challenge");
    auto challenge = json::getString(challengeBody, "challenge");
    if (!challenge)
        throw Error("auth", "Server did not return a challenge");

    // 2. Sign
    std::string signature = signer_
        ? signer_->signPersonalSign(*challenge)
        : custodial_->signPersonalSign(player_id_, *challenge);

    // 3. Verify
    auto verifyBody = requireOk(
        impl_->rest.post("/v1/auth/verify",
                         json::build({{"wallet", wallet_},
                                      {"signature", signature},
                                      {"challenge", *challenge}})),
        "auth/verify");
    auto token = json::getString(verifyBody, "token");
    if (!token)
        throw Error("auth", "Server did not return a token");
    token_ = *token;
    impl_->rest.setBearerToken(token_);

    Player p;
    p.wallet = wallet_;
    p.region = "na";
    p.language = "en";
    return p;
}

void AMPClient::logout() {
    token_.clear();
    impl_->rest.clearToken();
    disconnect();
}

// ── Player ─────────────────────────────────────────────────────

std::string AMPClient::me() {
    return requireOk(impl_->rest.get("/v1/me"), "me");
}

std::string AMPClient::getPlayer(const std::string& wallet) {
    return requireOk(impl_->rest.get("/v1/players/" + wallet), "players");
}

// ── Games ──────────────────────────────────────────────────────

std::string AMPClient::games() {
    return requireOk(impl_->rest.get("/v1/games"), "games");
}

// ── Queue ──────────────────────────────────────────────────────

std::string AMPClient::joinQueue(const std::string& gameId, const std::string& rulesetId) {
    return requireOk(impl_->rest.post("/v1/queue/join",
                                      json::build({{"gameId", gameId},
                                                   {"rulesetId", rulesetId}})),
                     "queue/join");
}

std::string AMPClient::leaveQueue() {
    return requireOk(impl_->rest.post("/v1/queue/leave", "{}"), "queue/leave");
}

std::string AMPClient::queueStatus() {
    return requireOk(impl_->rest.get("/v1/queue/status"), "queue/status");
}

std::string AMPClient::playBot() {
    return requireOk(impl_->rest.post("/v1/queue/play-bot", "{}"), "queue/play-bot");
}

// ── Matches (1v1) ──────────────────────────────────────────────

std::string AMPClient::getMatch(const std::string& matchId) {
    return requireOk(impl_->rest.get("/v1/matches/" + matchId), "matches/get");
}

std::string AMPClient::matchHistory(int limit, int offset) {
    std::string qs = "?limit=" + std::to_string(limit) + "&offset=" + std::to_string(offset);
    return requireOk(impl_->rest.get("/v1/matches/history" + qs), "matches/history");
}

std::string AMPClient::reportMatch(const std::string& matchId, const std::string& result,
                                   const std::string& transcriptHash) {
    std::optional<std::string> signature;
    if (signer_ || custodial_) {
        auto message = crypto::buildReportMessage(matchId, result);
        signature = signer_
            ? signer_->signPersonalSign(message)
            : custodial_->signPersonalSign(player_id_, message);
    }
    return requireOk(impl_->rest.post("/v1/matches/" + matchId + "/report",
                                      json::build({{"result", result},
                                                   {"transcriptHash", transcriptHash.empty()
                                                       ? std::nullopt
                                                       : std::optional<std::string>(transcriptHash)},
                                                   {"signature", signature}})),
                     "matches/report");
}

// ── Parties ────────────────────────────────────────────────────

std::string AMPClient::createParty(const std::string& gameId, const std::string& rulesetId) {
    return requireOk(impl_->rest.post("/v1/parties",
                                      json::build({{"game_id", gameId},
                                                   {"ruleset_id", rulesetId}})),
                     "parties/create");
}

std::string AMPClient::joinParty(const std::string& inviteCode) {
    std::string upper = inviteCode;
    for (auto& c : upper) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return requireOk(impl_->rest.post("/v1/parties/join",
                                      json::build({{"invite_code", upper}})),
                     "parties/join");
}

std::string AMPClient::getParty(const std::string& partyId) {
    return requireOk(impl_->rest.get("/v1/parties/" + partyId), "parties/get");
}

std::string AMPClient::lockParty(const std::string& partyId) {
    return requireOk(impl_->rest.post("/v1/parties/" + partyId + "/lock", "{}"),
                     "parties/lock");
}

std::string AMPClient::disbandParty(const std::string& partyId) {
    return requireOk(impl_->rest.post("/v1/parties/" + partyId + "/disband", "{}"),
                     "parties/disband");
}

// ── Multiplayer (N-player) ─────────────────────────────────────

MultiCommitResult AMPClient::multiCommit(const std::string& gameId, uint64_t stakeWei,
                                          int lobbySize) {
    std::string salt = crypto::generateSalt();
    std::string commitHash = crypto::computeCommitHash(wallet_, stakeWei, salt);

    auto body = requireOk(impl_->rest.post("/v1/multi/commit",
                                           json::build({{"gameId", gameId},
                                                        {"commitHash", commitHash},
                                                        {"stakeWei", std::to_string(stakeWei)},
                                                        {"lobbySize", std::to_string(lobbySize)}})),
                          "multi/commit");

    MultiCommitResult out;
    out.salt = salt;
    out.committed = json::getBool(body, "committed").value_or(false);
    out.committed_count = static_cast<int>(json::getInt(body, "committedCount").value_or(0));
    out.ready = json::getBool(body, "ready").value_or(false);
    return out;
}

std::string AMPClient::multiReveal(const std::string& gameId, const std::string& rulesetId,
                                   const std::string& salt) {
    return requireOk(impl_->rest.post("/v1/multi/reveal",
                                      json::build({{"gameId", gameId},
                                                   {"rulesetId", rulesetId},
                                                   {"salt", salt}})),
                     "multi/reveal");
}

std::string AMPClient::getMultiMatch(const std::string& matchId) {
    return requireOk(impl_->rest.get("/v1/multi/" + matchId), "multi/get");
}

std::string AMPClient::multiReport(const std::string& matchId,
                                   const std::vector<std::pair<std::string, int>>& ranked,
                                   const std::string& transcriptHash,
                                   uint64_t sessionNonce,
                                   uint64_t chainId,
                                   const std::string& contractAddress) {
    std::optional<std::string> signature;
    if (signer_ || custodial_) {
        std::vector<std::string> placements;
        placements.reserve(ranked.size());
        for (const auto& [addr, place] : ranked) {
            (void)place;
            placements.push_back(addr);
        }

        auto typedData = crypto::buildLadderTypedData(
            chainId,
            contractAddress.empty() ? "0xcabf7b626172fE55d54f03c346563671AbcC77f7" : contractAddress,
            matchId,
            std::string("0x") + std::string(63, '0') + "1",
            placements,
            transcriptHash,
            sessionNonce);

        signature = signer_
            ? signer_->signTypedData(typedData)
            : custodial_->signTypedData(player_id_, typedData);
    }

    // ranked: [[address, place], ...]
    std::ostringstream rankedJson;
    rankedJson << "[";
    for (size_t i = 0; i < ranked.size(); i++) {
        if (i) rankedJson << ",";
        rankedJson << "[\"" << json::escape(ranked[i].first) << "\"," << ranked[i].second << "]";
    }
    rankedJson << "]";

    std::ostringstream body;
    body << "{\"ranked\":" << rankedJson.str()
         << ",\"transcriptHash\":\"" << json::escape(transcriptHash) << "\""
         << ",\"sessionNonce\":" << sessionNonce;
    if (signature) body << ",\"signature\":\"" << json::escape(*signature) << "\"";
    body << "}";

    return requireOk(impl_->rest.post("/v1/multi/" + matchId + "/report", body.str()),
                     "multi/report");
}

std::string AMPClient::multiClaim(const std::string& matchId) {
    return requireOk(impl_->rest.post("/v1/multi/" + matchId + "/claim", "{}"),
                     "multi/claim");
}

// ── Events ─────────────────────────────────────────────────────

AmpWebSocket& AMPClient::events() {
    if (!ws_) {
        if (token_.empty())
            throw Error("not_authenticated", "Login before subscribing to events");
        ws_ = std::make_unique<AmpWebSocket>(server_url_, token_);
    }
    return *ws_;
}

void AMPClient::disconnect() {
    if (ws_) {
        ws_->close();
        ws_.reset();
    }
}

} // namespace amp
