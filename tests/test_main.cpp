/**
 * AMP C++ SDK — Test Suite
 *
 * Tests: Keccak-256, crypto helpers, EIP-712 digest computation,
 * commit hash determinism, typed data construction.
 */

#include "amp/types.hpp"
#include <cassert>
#include <cstdio>
#include <set>
#include <cmath>

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

    // ── Summary ───────────────────────────────────────────────
    printf("\n═════════════════════════════════════════════════\n");
    printf(" Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("═════════════════════════════════════════════════\n");

    return tests_failed == 0 ? 0 : 1;
}
