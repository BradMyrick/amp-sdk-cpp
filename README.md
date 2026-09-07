# amp-sdk-cpp

**AMP SDK for C++ — ranked matchmaking, skill ratings, and on-chain settlement for games on Avalanche.**

For Unreal Engine, native C++ game servers, and embedded game clients. Pure C++17 with zero engine dependencies in the core library.

## Structure

```
amp-sdk-cpp/
├── include/amp/           # Public headers (pure C++17)
│   ├── types.hpp          # Interfaces, models, crypto declarations
│   └── client.hpp         # AMPClient + AmpWebSocket
├── src/
│   └── crypto/crypto.cpp  # Keccak-256, EIP-712, commit hashes
├── third_party/nayuki/    # Keccak-256 (MIT, header-only)
├── examples/
│   └── quick_start.cpp    # Full lifecycle walkthrough
├── tests/
│   └── test_main.cpp      # 31 tests (crypto + EIP-712 + encoding)
└── AmpUnreal/             # Unreal Engine plugin (coming soon)
```

## Quickstart

```cpp
#include "amp/client.hpp"

auto signer = std::make_shared<PrivateKeySigner>(privateKeyHex);
amp::AMPClient client("https://amp.playwithamp.xyz", signer);

// One gasless signature to log in
auto player = client.login();

// Join a ranked queue
client.joinQueue("amp-tactics", "ranked-1v1");

// Listen for match assignments (WebSocket)
client.events().on(amp::EventType::MatchFound, [](const std::string& json) {
    // Parse and start your game
});

// Report the result (auto-signs EIP-191)
client.reportMatch(matchId, "win");
```

## What AMP handles vs what you handle

| AMP handles | Your game handles |
|---|---|
| Skill ratings (Glicko-2) | Determining who won |
| Matchmaking queue + skill windows | Running the actual game |
| Match assignment (WebSocket push) | Game UI/UX |
| Result verification + settlement | Player experience |
| On-chain escrow + payouts | Your game's economy |
| Anti-collusion (commit-reveal) | Your game's rules |

## Crypto

The SDK implements Keccak-256 (from Nayuki's MIT-licensed library) and EIP-712 typed-data digest computation natively. For secp256k1 signing, bring your own library:

| Library | Use case |
|---|---|
| libsecp256k1 (Bitcoin Core) | Recommended — fastest, most audited |
| OpenSSL | Available everywhere |
| [web3.unreal](https://github.com/G7DAO/web3.unreal) | For Unreal Engine — includes signing + wallet integration |

For Unreal Engine games, the `AmpUnreal` plugin (coming soon) wraps this SDK with Blueprint nodes and engine-native HTTP/WebSocket.

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
./amp-tests
```

## Tests

31 tests covering:
- Keccak-256 known vectors (empty, "abc") + determinism
- Salt generation (format, uniqueness)
- Report message construction
- Commit hash (determinism, input sensitivity, encoding)
- EIP-712 typed data construction (domain, fields, message)
- EIP-712 digest (size, determinism, chain sensitivity)
- Hex encoding roundtrips

## License

Apache-2.0 (Keccak-256 from Nayuki: MIT)
