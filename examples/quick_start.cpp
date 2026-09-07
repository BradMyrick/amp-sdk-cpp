/**
 * AMP SDK — Quick Start Example
 *
 * Shows the full lifecycle: login → queue → match → report → result.
 * Copy the parts you need into your game (Unreal, native, etc.)
 */

#include "amp/client.hpp"
#include "amp/types.hpp"
#include <cstdio>
#include <thread>
#include <chrono>

using namespace amp;

// ═══════════════════════════════════════════════════════════════
// OPTION A: Server-side game (private key signer)
// ═══════════════════════════════════════════════════════════════
//
// #include "amp/signers/private_key_signer.hpp"
// auto signer = std::make_shared<PrivateKeySigner>(privateKeyHex);
// AMPClient amp("https://amp.playwithamp.xyz", signer);
//
// ═══════════════════════════════════════════════════════════════
// OPTION B: Unreal Engine game
// ═══════════════════════════════════════════════════════════════
//
// In Unreal, use the AmpUnreal plugin which wraps AMPClient with
// Blueprint nodes and UE's native HTTP/WebSocket modules.
//
// UAMPSubsystem* amp = GetGameInstance()->GetSubsystem<UAMPSubsystem>();
// amp->Login();
// amp->JoinQueue("amp-tactics", "ranked-1v1");

int main() {
    printf("AMP SDK Quick Start\n");
    printf("===================\n\n");

    // 1. Create the client
    //    For server-side: use PrivateKeySigner
    //    For custodial: implement ICustodialProvider
    //    For Unreal: use the AmpUnreal plugin
    printf("1. Create AMPClient with your server URL and signer\n");
    printf("   auto amp = AMPClient(\"https://amp.playwithamp.xyz\", signer);\n\n");

    // 2. Login (one gasless signature)
    printf("2. Login — one gasless EIP-191 signature\n");
    printf("   auto player = amp.login();\n");
    printf("   // Internally: challenge → sign → verify → 7-day session token\n\n");

    // 3. Check available games
    printf("3. Check games\n");
    printf("   auto games = amp.games();\n");
    printf("   // Returns JSON: [{id, name, rulesets: [{id, name, queueDepth}]}]\n\n");

    // 4. Join a ranked queue
    printf("4. Join queue\n");
    printf("   auto result = amp.joinQueue(\"amp-tactics\", \"ranked-1v1\");\n");
    printf("   // Skill window starts at ±350 MMR and widens +8/sec\n\n");

    // 5. Listen for matches (WebSocket)
    printf("5. Listen for match\n");
    printf("   amp.events().on(EventType::MatchFound, [](const std::string& json) {\n");
    printf("       // Parse JSON, start your game\n");
    printf("   });\n\n");

    // 6. Report the result
    printf("6. Report result (auto-signs)\n");
    printf("   amp.reportMatch(matchId, \"win\");\n");
    printf("   // Signs EIP-191: AMP_REPORT:v1:{matchId}:{result}\n\n");

    // 7. Listen for the result (rating update)
    printf("7. Listen for result\n");
    printf("   amp.events().on(EventType::MatchResult, [](const std::string& json) {\n");
    printf("       // Rating: 1500 → 1552\n");
    printf("   });\n\n");

    printf("What AMP handles vs what you handle:\n");
    printf("  AMP: skill ratings, matchmaking, match assignment,\n");
    printf("       result verification, on-chain escrow, anti-collusion\n");
    printf("  You: determining who won, running the game, UI/UX\n\n");

    printf("Full API: login, games, queue (join/leave/status/bot),\n");
    printf("  match (get/report/history), party (create/join/lock/disband),\n");
    printf("  multiplayer (commit/reveal/report/claim), WebSocket events\n");

    return 0;
}
