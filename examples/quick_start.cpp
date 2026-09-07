/**
 * AMP SDK — Quick Start Example (runnable)
 *
 * The full 1v1 lifecycle against the production matchmaker:
 * login → queue → bot match → report → result.
 *
 * Copy the parts you need into your game (Unreal, native, etc).
 *
 * Build & run:
 *   mkdir build && cd build
 *   cmake .. -DCMAKE_BUILD_TYPE=Release && make
 *   AMP_TEST_KEY=0x... ./quick_start
 */

#include "amp/client.hpp"
#include "amp/signers/private_key_signer.hpp"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

using namespace amp;

static std::string loadKey() {
    if (const char* env = getenv("AMP_TEST_KEY"))
        return env;
    // Fallback: local e2e wallet file
    std::ifstream f("/tmp/opencode/e2e-wallets/wallets.json");
    std::stringstream ss;
    ss << f.rdbuf();
    std::string j = ss.str();
    auto pos = j.find("\"key\"");
    auto colon = j.find(':', pos);
    auto q1 = j.find('"', colon + 1);
    auto q2 = j.find('"', q1 + 1);
    return j.substr(q1 + 1, q2 - q1 - 1);
}

static std::string field(const std::string& body, const char* name) {
    auto pos = body.find(std::string("\"") + name + "\"");
    if (pos == std::string::npos) return "";
    auto colon = body.find(':', pos);
    auto p = body.find_first_not_of(" \t", colon + 1);
    if (p == std::string::npos || body[p] != '"') return ""; // null/non-string
    auto q2 = body.find('"', p + 1);
    return body.substr(p + 1, q2 - p - 1);
}

int main() {
  try {
    std::string key = loadKey();
    if (key.size() != 66) {
        printf("set AMP_TEST_KEY to a funded private key\n");
        return 1;
    }

    // 1. Create the client with a signer
    auto signer = std::make_shared<PrivateKeySigner>(key);
    AMPClient amp("https://amp.playwithamp.xyz", signer);

    // 2. Login — one gasless EIP-191 signature
    //    (challenge → sign → verify → 7-day session token)
    Player player = amp.login();
    printf("logged in: %s\n\n", player.wallet.c_str());

    // 3. See what's available
    std::string games = amp.games();
    printf("games: %.120s…\n\n", games.c_str());

    // 4. Session resume: if we already have a live match (crash,
    //    reconnect, stale client), continue it instead of re-queueing
    std::string meJson = amp.me();
    std::string liveId = field(meJson, "liveMatchId");
    std::string matchId;
    if (!liveId.empty()) {
        matchId = liveId;
        printf("resuming live match: %s\n\n", matchId.c_str());
    }

    // 5. Otherwise: join a ranked queue
    if (matchId.empty()) {
    amp.joinQueue("amp-tactics", "ranked-1v1");
    printf("queued — waiting for an opponent…\n");

    // 6. Wait for a human opponent (REST polling convenience — the
    //    AmpWebSocket gives you push events for production UIs), falling
    //    back to a bot when nobody is online:
    try {
        matchId = amp.waitForMatch(10000);
        printf("match found: %s\n\n", matchId.c_str());
    } catch (const Error&) {
        printf("no human opponent in 10s — playing a bot instead\n");
        amp.leaveQueue();
        std::string bot = amp.playBot();
        matchId = field(bot, "matchId");
        printf("bot match: %s\n\n", matchId.c_str());
    }
    } // end queue branch

    // 7. (your game runs here — QuickDraw, Tactics, whatever you built)

    // 8. Report the result — auto-signs EIP-191
    std::string rep = amp.reportMatch(matchId, "win");
    printf("reported: %.100s\n\n", rep.c_str());

    // 9. Check your rating moved
    std::string me = amp.me();
    printf("me: %.150s\n", me.c_str());

    amp.logout();
    printf("\ndone.\n");
    return 0;
  } catch (const Error& e) {
    printf("\nerror [%s]: %s\n", e.code.c_str(), e.message.c_str());
    return 1;
  }
}
