/**
 * AMP C++ SDK — Test Suite
 *
 * Tests: Keccak-256, crypto helpers, EIP-712 digest computation,
 * commit hash determinism, typed data construction.
 */

#include "amp/types.hpp"
#include "amp/client.hpp"
#include "amp/signers/private_key_signer.hpp"
#include <cassert>
#include <cstdio>
#include <cctype>
#include <set>
#include <cmath>
#include <fstream>
#include <sstream>
#include <atomic>
#include <chrono>
#include <thread>

#ifdef AMP_LIVE_TESTS
#include <cstdlib>
#endif

using namespace amp;
using namespace amp::crypto;

int tests_passed = 0, tests_failed = 0;

#define CHECK(desc, cond) do { \
    if (cond) { tests_passed++; printf("  ✓ %s\n", desc); } \
    else { tests_failed++; printf("  ✗ %s\n", desc); } \
} while (0)

int main() {
    printf("═════════════════════════════════════════════════\n");
    printf(" AMP C++ SDK Tests\n");
    printf("═════════════════════════════════════════════════\n\n");

    // ── Keccak-256 known vectors ────────────────────────────
    {
        printf("── Keccak-256 ──\n");

        // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        auto empty = keccak256({});
        auto emptyHex = toHex(empty.data(), empty.size());
        CHECK("keccak256(empty) matches known vector",
            emptyHex == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

        // keccak256("abc") = 0x4e03657aea45a94fc7d68ba826c5d2c39281ae27767bd7dc2c0775b0a66fd45f
        std::string abcStr = "abc";
        auto abc = keccak256({abcStr.begin(), abcStr.end()});
        auto abcHex = toHex(abc.data(), abc.size());
        CHECK("keccak256(abc) matches known vector",
            abcHex == "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

        // Determinism
        auto abc2 = keccak256({abcStr.begin(), abcStr.end()});
        CHECK("keccak256 is deterministic", abc == abc2);
    }

    // ── Salt generation ──────────────────────────────────────
    {
        printf("\n── Salt Generation ──\n");

        auto salt1 = generateSalt();
        CHECK("salt is 0x-prefixed", salt1.substr(0, 2) == "0x");
        CHECK("salt is 64 hex chars", salt1.length() == 66);

        // Uniqueness
        std::set<std::string> salts;
        for (int i = 0; i < 100; i++) salts.insert(generateSalt());
        CHECK("100 salts are unique", salts.size() == 100);
    }

    // ── Report message ────────────────────────────────────────
    {
        printf("\n── Report Message ──\n");

        auto msg = buildReportMessage("match-123", "win");
        CHECK("report message format", msg == "AMP_REPORT:v1:match-123:win");
        CHECK("loss format", buildReportMessage("m", "loss") == "AMP_REPORT:v1:m:loss");
        CHECK("draw format", buildReportMessage("m", "draw") == "AMP_REPORT:v1:m:draw");
    }

    // ── Commit hash ───────────────────────────────────────────
    {
        printf("\n── Commit Hash ──\n");

        std::string wallet = "0x95CC495dF579981d3Ffa4a8f77B93A17563E077a";
        auto hash1 = computeCommitHash(wallet, 1000, "test-salt");
        auto hash2 = computeCommitHash(wallet, 1000, "test-salt");
        CHECK("commit hash is deterministic", hash1 == hash2);
        CHECK("commit hash is 0x-prefixed 64 hex", hash1.length() == 66);

        auto wrongStake = computeCommitHash(wallet, 2000, "test-salt");
        auto wrongSalt = computeCommitHash(wallet, 1000, "other");
        CHECK("commit hash is stake-sensitive", hash1 != wrongStake);
        CHECK("commit hash is salt-sensitive", hash1 != wrongSalt);
    }

    // ── EIP-712 typed data construction ──────────────────────
    {
        printf("\n── EIP-712 Typed Data ──\n");

        auto td = buildLadderTypedData(
            43113,
            "0xcabf7b626172fE55d54f03c346563671AbcC77f7",
            "0x" + std::string(64, 'a'),
            "0x" + std::string(63, '0') + "1",
            {"0x95CC495dF579981d3Ffa4a8f77B93A17563E077a", "0x79aDcEF0E2bdc030f5906aA80C6B50C3712c0064"},
            "0x" + std::string(64, 'b'),
            42);

        CHECK("domain name", td.name == "AMPMultiplayer");
        CHECK("domain version", td.version == "1");
        CHECK("chain id", td.chain_id == 43113);
        CHECK("primary type", td.primary_type == "MultiplayerLadder");
        CHECK("5 fields in type", td.types["MultiplayerLadder"].size() == 5);
        CHECK("message has matchId", td.message.count("matchId") > 0);
        CHECK("message has sessionNonce", td.message.count("sessionNonce") > 0);
        CHECK("sessionNonce value", td.message["sessionNonce"] == "42");
    }

    // ── EIP-712 digest computation ────────────────────────────
    {
        printf("\n── EIP-712 Digest ──\n");

        auto td = buildLadderTypedData(
            43113,
            "0xcabf7b626172fE55d54f03c346563671AbcC77f7",
            "0x" + std::string(64, 'a'),
            "0x" + std::string(63, '0') + "1",
            {"0x95CC495dF579981d3Ffa4a8f77B93A17563E077a"},
            "0x" + std::string(64, 'b'),
            42);

        auto digest = computeEip712Digest(td);
        CHECK("digest is 32 bytes", digest.size() == 32);

        // Digest is deterministic
        auto digest2 = computeEip712Digest(td);
        CHECK("digest is deterministic", digest == digest2);

        // Digest is input-sensitive
        auto td2 = td;
        td2.chain_id = 1;
        auto digest3 = computeEip712Digest(td2);
        CHECK("digest is chain-sensitive", digest != digest3);
    }

    // ── Hex encoding ──────────────────────────────────────────
    {
        printf("\n── Hex Encoding ──\n");

        auto bytes = fromHex("0xdeadbeef");
        CHECK("fromHex parses 4 bytes", bytes.size() == 4);
        CHECK("fromHex first byte", bytes[0] == 0xde);
        CHECK("fromHex last byte", bytes[3] == 0xef);

        auto hex = toHex(bytes.data(), bytes.size());
        CHECK("toHex roundtrips", hex == "0xdeadbeef");

        auto empty = fromHex("0x");
        CHECK("fromHex handles empty", empty.empty());
    }

    // ── Commit hash encoding correctness ─────────────────────
    {
        printf("\n── Commit Hash Encoding ──\n");

        // Different wallets produce different hashes
        auto h1 = computeCommitHash("0x0000000000000000000000000000000000000001", 100, "salt");
        auto h2 = computeCommitHash("0x0000000000000000000000000000000000000002", 100, "salt");
        CHECK("different wallets → different hashes", h1 != h2);

        // Zero stake works
        auto h0 = computeCommitHash("0x95CC495dF579981d3Ffa4a8f77B93A17563E077a", 0, "");
        CHECK("zero stake + empty salt works", h0.length() == 66);
    }

    // ── Cross-SDK golden vector ───────────────────────────────
    {
        printf("\n── Cross-SDK Golden Vector ──\n");

        // Identical in the TS/C#/C++/Rust SDKs and amp-server:
        // keccak256(addr20 ‖ stake_u64_be(8) ‖ salt-utf8)
        auto golden = computeCommitHash(
            "0x95CC495dF579981d3Ffa4a8f77B93A17563E077a",
            1000000000000000ULL, "0xdeadbeef");
        std::string goldenLower = golden;
        for (auto& c : goldenLower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        CHECK("commit hash matches cross-SDK golden vector",
              goldenLower == "0x2d5491f1ad0117eea0c302b3cfb07590fef2d3892349e017361afd1bb5e5be10");
    }

    // ── Exit certificate message ──────────────────────────────
    {
        printf("\n── Exit Certificate Message ──\n");

        auto msg = buildExitCertMessage("m-42", 3, 1200, "0xabc");
        std::string expected =
            "AMP exit certificate\n\n"
            "Match: m-42\n"
            "Rank: 3\n"
            "Exit frame: 1200\n"
            "State hash: 0xabc\n\n"
            "This signature is free. It certifies your elimination and unlocks your reporting bond.";
        CHECK("exit cert message matches server format", msg == expected);
        CHECK("exit cert mentions reporting bond", msg.find("reporting bond.") != std::string::npos);
        CHECK("exit cert is rank-sensitive",
              buildExitCertMessage("m", 1, 1, "0x") != buildExitCertMessage("m", 2, 1, "0x"));
    }

    // ── Signer (OpenSSL secp256k1) ────────────────────────────
    {
        printf("\n── PrivateKeySigner ──\n");

        // Well-known vector: privkey = 1 → 0x7E5F...
        PrivateKeySigner signer("0x0000000000000000000000000000000000000000000000000000000000000001");
        std::string addr = signer.getAddress();
        CHECK("privkey=1 derives canonical address",
              strcasecmp(addr.c_str() + 2, "7E5F4552091A69125d5DfCb7b8C2659029395Bdf") == 0);

        auto sig = signer.signPersonalSign("hello");
        CHECK("signature is 0x + 130 hex chars", sig.size() == 132 && sig.substr(0, 2) == "0x");

        // Valid hex
        bool validHex = true;
        for (char c : sig.substr(2))
            if (!isxdigit(static_cast<unsigned char>(c))) validHex = false;
        CHECK("signature is valid hex", validHex);

        int v = std::stoi(sig.substr(130, 2), nullptr, 16);
        CHECK("v is 27 or 28", v == 27 || v == 28);

        // Different messages → different signatures
        auto sig2 = signer.signPersonalSign("hello2");
        CHECK("signatures are message-sensitive", sig != sig2);

        // EIP-712 signature is well-formed
        auto td = buildLadderTypedData(
            43113, "0xcabf7b626172fE55d54f03c346563671AbcC77f7",
            "0x" + std::string(64, 'a'), "0x" + std::string(63, '0') + "1",
            {"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"},
            "0x" + std::string(64, 'b'), 1);
        auto tsig = signer.signTypedData(td);
        CHECK("typed-data signature well-formed", tsig.size() == 132 && tsig.substr(0, 2) == "0x");

        // Rejects malformed keys
        bool threw = false;
        try { PrivateKeySigner bad("0x1234"); } catch (const std::invalid_argument&) { threw = true; }
        CHECK("rejects short private key", threw);
    }

#ifdef AMP_LIVE_TESTS
    // ── Live integration (production matchmaker) ─────────────
    {
        printf("\n── Live Integration ──\n");

        const char* serverEnv = getenv("AMP_SERVER");
        const char* keyEnv = getenv("AMP_TEST_KEY");
        std::string server = serverEnv ? serverEnv : "https://amp.playwithamp.xyz";
        std::string key = keyEnv ? keyEnv : "";

        if (key.empty()) {
            // Fall back to the local e2e wallet file
            std::ifstream kf(getenv("AMP_TEST_KEY_FILE")
                             ? getenv("AMP_TEST_KEY_FILE")
                             : "/tmp/opencode/e2e-wallets/wallets.json");
            if (kf.good()) {
                std::stringstream ss; ss << kf.rdbuf();
                std::string j = ss.str();
                auto pos = j.find("\"key\"");
                auto colon = j.find(':', pos);
                auto q1 = j.find('"', colon + 1);
                auto q2 = j.find('"', q1 + 1);
                key = j.substr(q1 + 1, q2 - q1 - 1);
            }
        }
        CHECK("have a test key", !key.empty());
        if (!key.empty()) {
            try {
                auto liveSigner = std::make_shared<PrivateKeySigner>(key);
                AMPClient client(server, liveSigner);

                // Login (challenge → EIP-191 sign → verify)
                Player p = client.login();
                CHECK("login returns wallet",
                      strcasecmp(p.wallet.c_str() + 2,
                                 liveSigner->getAddress().c_str() + 2) == 0);
                CHECK("client is authenticated", client.authenticated());

                // Games list
                std::string gamesJson = client.games();
                CHECK("games() returns a list", gamesJson.find("\"games\"") != std::string::npos);

                // Me
                std::string meJson = client.me();
                CHECK("me() returns wallet", meJson.find("\"wallet\"") != std::string::npos);

                // Queue join + status + leave
                std::string joinJson = client.joinQueue("amp-tactics", "ranked-1v1");
                CHECK("joinQueue accepted", joinJson.find("\"ticketId\"") != std::string::npos ||
                                             joinJson.find("\"queueDepth\"") != std::string::npos);
                std::string statusJson = client.queueStatus();
                CHECK("queueStatus works", !statusJson.empty());
                std::string leaveJson = client.leaveQueue();
                CHECK("leaveQueue works", leaveJson.find("\"left\"") != std::string::npos);

                // Play a bot and report the result
                std::string botJson = client.playBot();
                auto matchId = [&]() -> std::string {
                    auto pos = botJson.find("\"matchId\"");
                    if (pos == std::string::npos) return "";
                    auto colon = botJson.find(':', pos);
                    auto q1 = botJson.find('"', colon + 1);
                    auto q2 = botJson.find('"', q1 + 1);
                    return botJson.substr(q1 + 1, q2 - q1 - 1);
                }();
                CHECK("playBot returns a matchId", !matchId.empty());

                if (!matchId.empty()) {
                    std::string m = client.getMatch(matchId);
                    CHECK("getMatch works", m.find("\"id\"") != std::string::npos ||
                                             m.find("matchId") != std::string::npos);

                    std::string rep = client.reportMatch(matchId, "win");
                    CHECK("reportMatch accepted", rep.find("\"state\"") != std::string::npos);
                }

                // WebSocket: connect and expect a hello
                {
                    AmpWebSocket& ws = client.events();
                    std::atomic<bool> gotHello{false};
                    ws.on(EventType::Hello, [&](const std::string&) { gotHello = true; });
                    ws.connect();
                    // Wait up to 5s for hello
                    for (int i = 0; i < 50 && !gotHello; i++)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    CHECK("WebSocket receives hello event", gotHello);
                    ws.close();
                }

                client.logout();
                CHECK("logout clears auth", !client.authenticated());
            } catch (const Error& e) {
                printf("  live error: [%s] %s\n", e.code.c_str(), e.message.c_str());
                CHECK("live flow completed without errors", false);
            }
        }
    }
#endif

    // ── Summary ───────────────────────────────────────────────
    printf("\n═════════════════════════════════════════════════\n");
    printf(" Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("═════════════════════════════════════════════════\n");

    return tests_failed == 0 ? 0 : 1;
}
