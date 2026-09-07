# AmpUnreal — ranked multiplayer with wallets, in 5 minutes

**The absolute easiest way to add ranked matchmaking, skill ratings, and real-money competition to an Unreal Engine game. No blockchain knowledge required. No gas. No wallet UI to build.**

| What your team writes | What AMP handles |
|---|---|
| "Who won this match?" (one Blueprint node) | Glicko-2 skill ratings, queue + skill windows, match assignment, result verification, anti-cheat commit-reveal, on-chain escrow + payouts, fiat-friendly custodial rails |

```
AMP Login ──> AMP Join Queue ──> AMP Wait For Match ──> [your game] ──> AMP Report Match
   1 node        1 node             1 latent node                      1 node
```

That's a complete ranked multiplayer loop. Everything else (parties, N-player battle royale lobbies, staking, death certificates) follows the same pattern.

---

## Install (2 minutes)

1. Copy or submodule this folder into your project:
   ```
   YourProject/Plugins/AmpUnreal/
   ```
2. Enable the **WebSockets** plugin (Edit → Plugins → search "WebSockets").
3. Regenerate project files and build. Done — no crypto dependencies to install; OpenSSL ships with the engine.

> Requires UE 5.1+ (developed against the UE5 API surface; supports Win64, Mac, Linux, Android, iOS).

## Your first ranked match (3 minutes)

Open your game-mode Blueprint. Right-click → search **AMP**:

```text
Begin Play
   └─ AMP Login (DevPrivateKey = your test key)
        ├─ On Success ──> AMP Join Queue ("amp-tactics", "ranked-1v1")
        │                    └─ On Success ──> AMP Wait For Match (30s)
        │                                         ├─ On Found ──> Start your match level
        │                                         └─ On Timeout ──> AMP Play Bot
        └─ On Error ──> Print (Error.Message)
```

When your game ends:

```text
Game Over
   └─ AMP Report Match (MatchId, Win)   ← auto-signs, gasless, instant
        └─ On Success ──> Show new rating (On Match Result event)
```

**That's the whole integration.** The player never sees a wallet, never pays gas, never signs anything visible — one invisible EIP-191 signature at login powers the entire skill-verified economy.

## The node set

### Core
| Node | Success pin returns | Notes |
|---|---|---|
| **AMP Login** | `FAMPPlayer` | One gasless signature. Connects the live event stream automatically. |
| **AMP Get Games** | `TArray<FAMPGameInfo>` | Live queue depths per ruleset. |
| **AMP Me** | raw JSON | Your wallet, ratings, live match id. |
| **AMP Get Player** | raw JSON | Any player's public profile + history. |

### Queue & 1v1
| Node | Returns | Notes |
|---|---|---|
| **AMP Join Queue** | raw JSON | Glicko-2 skill-window matchmaking starts. |
| **AMP Leave Queue** | raw JSON | |
| **AMP Queue Status** | `FAMPQueueStatus` | depth / waitedMs / skillWindow. |
| **AMP Play Bot** | MatchId | Instant practice match, house bot at your rating. |
| **AMP Wait For Match** | `FAMPMatchFound` | Latent node — WebSocket push with 2 s REST fallback. |
| **AMP Get Match** / **AMP Match History** | raw JSON | |
| **AMP Report Match** | raw JSON | Win/Loss/Draw — auto-signs EIP-191. |
| **AMP Verify Escrow** | raw JSON | For staked matches — flips escrow_pending → live. |

### Parties
| Node | Returns |
|---|---|
| **AMP Create Party** | `FAMPPartyCreated` (share `InviteCode`) |
| **AMP Join Party** | raw JSON |
| **AMP Lock Party** / **AMP Disband Party** | raw JSON |

### N-player FFA (battle royale, etc.)
| Node | Returns | Notes |
|---|---|---|
| **AMP Multi Commit** | `FAMPMultiCommit` — **keep `Salt`** | Commit-reveal: the server can't see your stake until reveal, so nobody can front-run lobby selection. |
| **AMP Multi Reveal** | raw JSON | Pass the `Salt` from commit. |
| **AMP Submit Exit Cert** | raw JSON | Player eliminated? Sign rank + state hash and disconnect — auto-signs EIP-191, unlocks the reporting bond. |
| **AMP Countersign Exit Cert** | raw JSON | Survivors verify an eliminated player's state hash. |
| **AMP Multi Report** | raw JSON | Final ladder, best-first — auto-signs EIP-712. Quorum settles. |
| **AMP Multi Claim** | raw JSON | Trigger settlement + payouts. |

## Live events (bind on the subsystem)

`GetGameInstanceSubsystem("AMPSubsystem")` → bind any of:

| Event | Payload |
|---|---|
| **On Match Found** | `FAMPMatchFound` (opponent wallet, rating, expiry) |
| **On Match Result** | `FAMPMatchResult` (rating before/after) |
| **On Queue Status** | `FAMPQueueStatus` |
| **On Multi Lobby Formed** | `FAMPMultiLobbyFormed` |
| **On Multi Result** / **On Multi Cancelled** / **On Match Update** | raw JSON |
| **On Events Connected** / **On Events Closed** | auto-reconnects after 5 s |

All events fire **on the game thread** — bind directly to widgets and gameplay code.

## Auth models (same dual-path as every AMP SDK)

1. **Dev & dedicated servers** — pass a private key to `AMP Login` (or `SetDevPrivateKey`). OpenSSL secp256k1, RFC-vectors-verified. **Never ship player keys in clients.**
2. **Player wallets** — implement `FAMPSigner` in C++ (one header, three methods) and bridge to your wallet plugin / platform wallet, then `Subsystem->SetCustomSigner(...)`.
3. **Custodial (fiat players)** — same interface; your backend signs on behalf of players. AMP never touches fiat; your game is the bridge, like Stripe rails.

## Configuration (optional)

```ini
; DefaultGame.ini
[/Script/AmpUnreal.AMPSubsystem]
ServerUrl=https://amp.playwithamp.xyz
ChainId=43113
ContractAddress=0xcabf7b626172fE55d54f03c346563671AbcC77f7
```

## What's inside (for engine-source readers)

```
Source/AmpUnreal/
├── Public/
│   ├── AMPTypes.h            # USTRUCTs (BlueprintType)
│   ├── AMPSigner.h           # wallet-bridge interface
│   ├── AMPPrivateKeySigner.h # OpenSSL dev/server signer
│   ├── AMPSubsystem.h        # session, REST, WS, events
│   └── AMPAsyncActions.h     # every Blueprint async node
├── Private/
│   ├── AMPSubsystem.cpp      # UE HTTP/WebSockets + game-thread marshaling
│   ├── AMPAsyncActions.cpp   # node implementations (auto-signing)
│   ├── AMPPrivateKeySigner.cpp
│   └── AmpCore/              # engine-free protocol core (vendored)
```

**AmpCore** is the same byte-for-byte protocol core shipped in the TS/C#/C++/Rust SDKs (Keccak-256, commit hashes, EIP-712 digests) — compiled under UE's `-fno-exceptions -fno-rtti` and pinned to the cross-SDK golden vector:

```
keccak256(addr20 ‖ stake8 ‖ salt-utf8) → 0x2d5491f1ad0117eea0c302b3cfb07590fef2d3892349e017361afd1bb5e5be10
```

Transport uses engine modules (`HTTP`, `WebSockets`, `Json`) — platform proxies and certificate stores just work. Signing uses the engine's OpenSSL.

## Security notes

- The dev private key path logs a loud warning — it's for development and dedicated servers only.
- Session tokens are 7-day bearer tokens; keep them in memory (the subsystem does).
- Commit-reveal means the matchmaker can't collude on lobby composition; exit certificates mean eliminated players can disconnect without trusting a relay; EIP-712 ladders mean settlement requires survivor quorum — not the server's word.

## Unity?

The C# SDK (github.com/BradMyrick/amp-sdk-csharp) is Unity-ready — same API shape, Nethereum signing. A native Unity package wrapper is on the roadmap.

## License

Apache-2.0 (Keccak-256 from Nayuki: MIT).
