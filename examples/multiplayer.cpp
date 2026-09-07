/**
 * AMP SDK — N-Player Multiplayer Example
 *
 * The full staked FFA lifecycle: commit-reveal anti-collusion, live
 * play with death certificates, EIP-712 ladder reporting, settlement.
 *
 * Build & run:
 *   cmake .. -DCMAKE_BUILD_TYPE=Release && make multiplayer
 *   AMP_TEST_KEY=0x... ./multiplayer
 */

#include "amp/client.hpp"
#include "amp/signers/private_key_signer.hpp"
#include "amp/http_client.hpp"
#include "../src/json.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

using namespace amp;

static std::string loadKey() {
    if (const char* env = getenv("AMP_TEST_KEY")) return env;
    std::ifstream f("/tmp/opencode/e2e-wallets/wallets.json");
    std::stringstream ss; ss << f.rdbuf();
    std::string j = ss.str();
    auto pos = j.find("\"key\"");
    auto colon = j.find(':', pos);
    auto q1 = j.find('"', colon + 1);
    auto q2 = j.find('"', q1 + 1);
    return j.substr(q1 + 1, q2 - q1 - 1);
}

static std::string field(const std::string& body, const char* name) {
    auto v = json::getString(body, name);
    return v.value_or("");
}

int main() {
    auto signer = std::make_shared<PrivateKeySigner>(loadKey());
    AMPClient amp("https://amp.playwithamp.xyz", signer);

    // ═══ 1. LOGIN + COMMIT — stake into the FFA queue ═════════
    amp.login();
    printf("logged in: %s\n", amp.wallet().c_str());

    // multiCommit generates the salt internally and returns it — KEEP IT.
    // The server only sees keccak256(wallet ‖ stake ‖ salt) until reveal,
    // so neither the server nor other players can front-run your stake.
    MultiCommitResult commit = amp.multiCommit("amp-tactics", 0 /* stakeWei */, 4);
    printf("committed (%d/4 waiting), salt: %.18s…\n",
           commit.committed_count, commit.salt.c_str());

    // ═══ 2. REVEAL — open your commit ═════════════════════════
    std::string reveal = amp.multiReveal("amp-tactics", "ranked-1v1", commit.salt);
    printf("revealed: %s\n\n", reveal.c_str());

    // ═══ 3. WAIT FOR LOBBY (WebSocket push in production) ═════
    // Subscribe with amp.events().on(EventType::MultiLobbyFormed, …)
    // The lobby forms when 4 players have committed + revealed.

    // ═══ 4. PLAY — death certs when players are eliminated ═══
    // When YOUR player dies, sign and submit, then you can disconnect:
    //
    //   amp.submitExitCert(matchId, /*rank=*/3, /*exitFrame=*/1200,
    //                      /*stateHash=*/"0x…");
    //
    // Survivors countersign each cert against their own simulation:
    //
    //   amp.countersignExitCert(matchId, eliminatedWallet, "0x…");

    // ═══ 5. REPORT — last survivor submits the ladder ════════
    // [winner, second, third, …] — best to worst. Auto-signs EIP-712:
    //
    //   amp.multiReport(matchId,
    //       { {winnerWallet, 1}, {secondWallet, 2}, {thirdWallet, 3} },
    //       /*transcriptHash=*/"0x…", /*sessionNonce=*/42);

    // ═══ 6. CLAIM — trigger settlement ═══════════════════════
    //   amp.multiClaim(matchId);

    amp.logout();
    printf("\ndone.\n");
    return 0;
}
