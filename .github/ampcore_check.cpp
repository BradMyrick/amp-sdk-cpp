// AmpUnreal CI — validates the vendored AmpCore under UE build flags.
// Golden vectors are shared by all AMP SDKs (TS/C#/C++/Rust) + amp-server.
#include "AmpCore.h"
#include <cstdio>
#include <cstring>
using namespace ampcore;

int main() {
    // keccak256("")
    if (toHex(keccak256({}).data(), 32) !=
        "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") return 2;

    // Commit hash golden vector (ethers-verified)
    auto h = computeCommitHash("0x95CC495dF579981d3Ffa4a8f77B93A17563E077a",
                               1000000000000000ULL, "0xdeadbeef");
    if (h != "0x2d5491f1ad0117eea0c302b3cfb07590fef2d3892349e017361afd1bb5e5be10") {
        printf("FAIL commit hash: %s\n", h.c_str()); return 3;
    }

    // EIP-191 determinism
    auto d1 = eip191Digest("hello"), d2 = eip191Digest("hello");
    if (d1.size() != 32 || memcmp(d1.data(), d2.data(), 32) != 0) return 4;

    // Exit-cert message format
    auto msg = buildExitCertMessage("m-42", 3, 1200, "0xabc");
    if (msg.find("AMP exit certificate") != 0 || msg.find("reporting bond.") == std::string::npos) return 5;

    // EIP-712 golden digest (ethers-verified, contract typehash: gameId is bytes32)
    auto td = buildLadderTypedData(43113, "0xcabf7b626172fE55d54f03c346563671AbcC77f7",
                                   "0x" + std::string(64,'a'), "0x" + std::string(63,'0') + "1",
                                   {"0x95CC495dF579981d3Ffa4a8f77B93A17563E077a",
                                    "0x79aDcEF0E2bdc030f5906aA80C6B50C3712c0064"},
                                   "0x" + std::string(64,'b'), 42);
    auto dg = toHex(computeEip712Digest(td).data(), 32);
    if (dg != "0x7e3467e6d14daf2c2ba195a1147c550a480c30c867c202b7b02e385a8e48123f") {
        printf("FAIL eip712: %s\n", dg.c_str()); return 6;
    }

    printf("AMP CORE VALIDATED (keccak + commit golden + EIP-191 + EIP-712 golden)\n");
    return 0;
}
