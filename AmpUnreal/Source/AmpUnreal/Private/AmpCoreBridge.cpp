/**
 * AmpCoreBridge — implementation. ENGINE-FREE translation unit:
 * no UE headers, no shared PCH. Includes the vendored AmpCore (std C++)
 * and OpenSSL (secp256k1 signing) — neither may appear in UE TUs.
 */

#include "AmpCoreBridge.h"
#include "AmpCore/AmpCore.h"

// UBT force-includes Definitions → ObjectMacros.h into every module TU,
// which declares `namespace UI` — colliding with OpenSSL's `typedef
// struct ui_st UI`. Macro-rename OpenSSL's UI for the duration of these
// includes (we never use OpenSSL's UI API, and all its internal uses
// rename consistently).
#define UI AmpOpenSSLUI
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#undef UI

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include <string>
#include <vector>
#include <cstring>

namespace {

char* safeCopy(char* dst, size_t cap, const std::string& src)
{
    if (cap == 0) return dst;
    size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
    return dst;
}

// ── OpenSSL signer (port of the verified amp-sdk-cpp algorithm) ──

struct KeyGuard
{
    EC_KEY* key = nullptr;
    ~KeyGuard() { if (key) EC_KEY_free(key); }
};

bool loadKey(const char* keyHex, KeyGuard& guard, std::string& outErr)
{
    std::string hex = keyHex ? keyHex : "";
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex = hex.substr(2);
    if (hex.size() != 64) { outErr = "private key must be 64 hex chars"; return false; }

    BIGNUM* priv = nullptr;
    if (!BN_hex2bn(&priv, hex.c_str()) || BN_is_zero(priv))
    {
        if (priv) BN_clear_free(priv);
        outErr = "invalid private key";
        return false;
    }

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) { BN_clear_free(priv); outErr = "secp256k1 unavailable"; return false; }

    if (EC_KEY_set_private_key(key, priv) != 1)
    {
        BN_clear_free(priv); EC_KEY_free(key);
        outErr = "private key out of range";
        return false;
    }

    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(group);
    if (!pub || EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr) != 1 ||
        EC_KEY_set_public_key(key, pub) != 1)
    {
        if (pub) EC_POINT_free(pub);
        BN_clear_free(priv); EC_KEY_free(key);
        outErr = "failed to derive public key";
        return false;
    }
    EC_POINT_free(pub);
    BN_clear_free(priv);

    guard.key = key;
    return true;
}

std::string bytesToHex(const uint8_t* data, size_t len)
{
    static const char* digits = "0123456789abcdef";
    std::string out = "0x";
    for (size_t i = 0; i < len; i++)
    {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xF];
    }
    return out;
}

int findRecoveryId(const EC_KEY* key, const uint8_t hash[32],
                   const BIGNUM* r, const BIGNUM* sLow)
{
    const EC_GROUP* group = EC_KEY_get0_group(key);
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* x = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* rInv = BN_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    BN_bin2bn(hash, 32, e);

    EC_POINT* R = EC_POINT_new(group);
    EC_POINT* sR = EC_POINT_new(group);
    EC_POINT* eG = EC_POINT_new(group);
    EC_POINT* Q = EC_POINT_new(group);

    int found = -1;
    for (int recid = 0; recid < 2 && found < 0; recid++)
    {
        BN_copy(x, r);
        if (!EC_POINT_set_compressed_coordinates(group, R, x, recid & 1, ctx)) continue;
        if (!EC_POINT_mul(group, eG, e, nullptr, nullptr, ctx)) continue;
        if (!EC_POINT_mul(group, sR, nullptr, R, sLow, ctx)) continue;
        if (!EC_POINT_invert(group, eG, ctx)) continue;
        if (!EC_POINT_add(group, Q, sR, eG, ctx)) continue;
        if (!BN_mod_inverse(rInv, r, order, ctx)) continue;
        if (!EC_POINT_mul(group, Q, nullptr, Q, rInv, ctx)) continue;
        if (!EC_POINT_is_on_curve(group, Q, ctx)) continue;
        if (EC_POINT_cmp(group, Q, EC_KEY_get0_public_key(key), ctx) == 0)
            found = recid;
    }

    BN_free(x); BN_free(e); BN_free(rInv); BN_free(order);
    EC_POINT_free(R); EC_POINT_free(sR); EC_POINT_free(eG); EC_POINT_free(Q);
    BN_CTX_free(ctx);
    return found;
}

std::string signDigest(EC_KEY* key, const uint8_t digest[32], std::string& outErr)
{
    ECDSA_SIG* sig = ECDSA_do_sign(digest, 32, key);
    if (!sig) { outErr = "OpenSSL signing failed"; return {}; }

    const BIGNUM* r = ECDSA_SIG_get0_r(sig);
    const BIGNUM* s = ECDSA_SIG_get0_s(sig);

    // EIP-2 low-s normalization
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    BIGNUM* half = BN_new();
    BIGNUM* sLow = BN_dup(s);
    EC_GROUP_get_order(EC_KEY_get0_group(key), order, ctx);
    BN_rshift1(half, order);
    if (BN_cmp(s, half) > 0)
        BN_sub(sLow, order, s);

    int recid = findRecoveryId(key, digest, r, sLow);
    if (recid < 0)
    {
        BN_free(sLow); BN_free(order); BN_free(half);
        BN_CTX_free(ctx); ECDSA_SIG_free(sig);
        outErr = "failed to compute recovery id";
        return {};
    }

    uint8_t out[65] = {0};
    BN_bn2binpad(r, out, 32);
    BN_bn2binpad(sLow, out + 32, 32);
    out[64] = static_cast<uint8_t>(27 + recid);

    BN_free(sLow); BN_free(order); BN_free(half);
    BN_CTX_free(ctx);
    ECDSA_SIG_free(sig);
    return bytesToHex(out, 65);
}

} // namespace

// ── C ABI ───────────────────────────────────────────────────────

extern "C" {

const char* amp_address(const char* private_key_hex)
{
    static thread_local char addr[43];
    KeyGuard guard;
    std::string err;
    if (!loadKey(private_key_hex, guard, err)) return nullptr;

    const EC_GROUP* group = EC_KEY_get0_group(guard.key);
    const EC_POINT* pub = EC_KEY_get0_public_key(guard.key);
    size_t pubLen = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                       nullptr, 0, nullptr);
    if (pubLen == 0) return nullptr;
    std::vector<uint8_t> raw(pubLen);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                       raw.data(), pubLen, nullptr);

    std::vector<uint8_t> body(raw.begin() + 1, raw.end());
    std::vector<uint8_t> hash = ampcore::keccak256(body);
    safeCopy(addr, sizeof(addr), bytesToHex(hash.data() + 12, 20));
    return addr;
}

int amp_sign_eip191(const char* private_key_hex, const char* message_utf8,
                    char* out_sig, size_t sig_cap)
{
    KeyGuard guard;
    std::string err;
    if (!loadKey(private_key_hex, guard, err)) return 1;

    std::vector<uint8_t> digest = ampcore::eip191Digest(message_utf8 ? message_utf8 : "");
    std::string sig = signDigest(guard.key, digest.data(), err);
    if (sig.empty()) return 2;
    safeCopy(out_sig, sig_cap, sig);
    return 0;
}

int amp_sign_digest(const char* private_key_hex, const uint8_t digest[32],
                    char* out_sig, size_t sig_cap)
{
    KeyGuard guard;
    std::string err;
    if (!loadKey(private_key_hex, guard, err)) return 1;

    std::string sig = signDigest(guard.key, digest, err);
    if (sig.empty()) return 2;
    safeCopy(out_sig, sig_cap, sig);
    return 0;
}

void amp_eip191_digest(const char* message_utf8, uint8_t out_digest[32])
{
    std::vector<uint8_t> d = ampcore::eip191Digest(message_utf8 ? message_utf8 : "");
    std::memcpy(out_digest, d.data(), 32);
}

void amp_commit_hash(const char* wallet, uint64_t stake_wei, const char* salt,
                     char* out_hash, size_t hash_cap)
{
    std::string h = ampcore::computeCommitHash(wallet ? wallet : "",
                                               stake_wei, salt ? salt : "");
    safeCopy(out_hash, hash_cap, h);
}

void amp_generate_salt(char* out_salt, size_t salt_cap)
{
    safeCopy(out_salt, salt_cap, ampcore::generateSalt());
}

void amp_ladder_digest(uint64_t chain_id, const char* contract_address,
                       const char* match_id, const char* const* ranked_wallets,
                       int wallet_count, const char* transcript_hash,
                       uint64_t session_nonce, uint8_t out_digest[32])
{
    std::vector<std::string> placements;
    for (int i = 0; i < wallet_count; i++)
        placements.push_back(ranked_wallets[i] ? ranked_wallets[i] : "");

    ampcore::Eip712TypedData td = ampcore::buildLadderTypedData(
        chain_id, contract_address ? contract_address : "",
        match_id ? match_id : "", "1", placements,
        transcript_hash ? transcript_hash : "", session_nonce);

    std::vector<uint8_t> d = ampcore::computeEip712Digest(td);
    std::memcpy(out_digest, d.data(), 32);
}

void amp_exit_cert_message(const char* match_id, int rank, uint64_t exit_frame,
                           const char* state_hash, char* out_message, size_t message_cap)
{
    std::string m = ampcore::buildExitCertMessage(
        match_id ? match_id : "", rank, exit_frame, state_hash ? state_hash : "");
    safeCopy(out_message, message_cap, m);
}

void amp_report_message(const char* match_id, const char* result,
                        char* out_message, size_t message_cap)
{
    std::string m = ampcore::buildReportMessage(match_id ? match_id : "",
                                                result ? result : "");
    safeCopy(out_message, message_cap, m);
}

} // extern "C"
