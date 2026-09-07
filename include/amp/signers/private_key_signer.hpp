/**
 * AMP SDK — Private-key signer using OpenSSL secp256k1.
 *
 * Signs EIP-191 (personal_sign) and EIP-712 (typed data) digests.
 * Produces 65-byte r‖s‖v signatures with v ∈ {27, 28}, low-s normalized
 * (EIP-2), and the recovery id found by public-key matching.
 *
 * Server-side / testing / trusted-game-client use only.
 */

#pragma once

#include "amp/types.hpp"

// EC_KEY APIs are deprecated in OpenSSL 3.x but remain fully functional
// and are the simplest portable path across game-platform OpenSSL builds.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#pragma GCC diagnostic pop

#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>

namespace amp {

class PrivateKeySigner : public ISigner {
public:
    explicit PrivateKeySigner(const std::string& privateKeyHex) {
        std::string hex = privateKeyHex;
        if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
            hex = hex.substr(2);
        if (hex.size() != 64)
            throw std::invalid_argument("Private key must be 64 hex chars");

        BIGNUM* priv = nullptr;
        if (!BN_hex2bn(&priv, hex.c_str()) || BN_is_zero(priv))
            throw std::invalid_argument("Invalid private key");

        key_ = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!key_) { BN_clear_free(priv); throw std::runtime_error("secp256k1 unavailable"); }

        if (EC_KEY_set_private_key(key_, priv) != 1) {
            BN_clear_free(priv); EC_KEY_free(key_); key_ = nullptr;
            throw std::runtime_error("Private key out of secp256k1 range");
        }

        const EC_GROUP* group = EC_KEY_get0_group(key_);
        EC_POINT* pub = EC_POINT_new(group);
        if (!pub || EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr) != 1 ||
            EC_KEY_set_public_key(key_, pub) != 1) {
            if (pub) EC_POINT_free(pub);
            BN_clear_free(priv); EC_KEY_free(key_); key_ = nullptr;
            throw std::runtime_error("Failed to derive public key");
        }
        EC_POINT_free(pub);
        BN_clear_free(priv);

        address_ = deriveAddress(key_);
    }

    ~PrivateKeySigner() override {
        if (key_) EC_KEY_free(key_);
    }

    PrivateKeySigner(const PrivateKeySigner&) = delete;
    PrivateKeySigner& operator=(const PrivateKeySigner&) = delete;

    std::string getAddress() override { return address_; }

    std::string signPersonalSign(const std::string& message) override {
        std::string prefixed = std::string("\x19", 1) +
                               "Ethereum Signed Message:\n" +
                               std::to_string(message.size()) + message;
        auto digest = crypto::keccak256({prefixed.begin(), prefixed.end()});
        return signDigest(digest);
    }

    std::string signTypedData(const Eip712TypedData& data) override {
        return signDigest(crypto::computeEip712Digest(data));
    }

private:
    EC_KEY* key_ = nullptr;
    std::string address_;

    static std::string toHexStr(const uint8_t* data, size_t len) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++) oss << std::setw(2) << static_cast<int>(data[i]);
        return oss.str();
    }

    /// Try each recovery id; return the one whose recovered key matches ours.
    int findRecoveryId(const uint8_t hash[32], const BIGNUM* r, const BIGNUM* sLow) {
        const EC_GROUP* group = EC_KEY_get0_group(key_);
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
        for (int recid = 0; recid < 4 && found < 0; recid++) {
            BN_copy(x, r);
            if (recid >= 2 && !BN_uadd(x, x, order)) continue;

            if (!EC_POINT_set_compressed_coordinates(group, R, x, recid & 1, ctx))
                continue;
            if (!EC_POINT_mul(group, eG, e, nullptr, nullptr, ctx))
                continue;
            if (!EC_POINT_mul(group, sR, nullptr, R, sLow, ctx))
                continue;
            if (!EC_POINT_invert(group, eG, ctx))
                continue;
            // Q = r^-1 * (sR - eG)
            if (!EC_POINT_add(group, Q, sR, eG, ctx))
                continue;
            if (!BN_mod_inverse(rInv, r, order, ctx))
                continue;
            if (!EC_POINT_mul(group, Q, nullptr, Q, rInv, ctx))
                continue;
            if (!EC_POINT_is_on_curve(group, Q, ctx))
                continue;
            if (EC_POINT_cmp(group, Q, EC_KEY_get0_public_key(key_), ctx) == 0)
                found = recid;
        }

        BN_free(x); BN_free(e); BN_free(rInv); BN_free(order);
        EC_POINT_free(R); EC_POINT_free(sR); EC_POINT_free(eG); EC_POINT_free(Q);
        BN_CTX_free(ctx);
        return found;
    }

    std::string signDigest(const std::vector<uint8_t>& digest) {
        if (digest.size() != 32)
            throw std::runtime_error("Digest must be 32 bytes");

        ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), 32, key_);
        if (!sig) throw std::runtime_error("Signing failed");

        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);

        // Low-s normalization (EIP-2)
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* order = BN_new();
        BIGNUM* half = BN_new();
        BIGNUM* sLow = BN_dup(s);
        EC_GROUP_get_order(EC_KEY_get0_group(key_), order, ctx);
        BN_rshift1(half, order);
        if (BN_cmp(s, half) > 0) {
            BN_sub(sLow, order, s);
        }

        int recid = findRecoveryId(digest.data(), r, sLow);
        if (recid < 0) {
            BN_free(sLow); BN_free(order); BN_free(half); BN_CTX_free(ctx);
            ECDSA_SIG_free(sig);
            throw std::runtime_error("Failed to compute recovery id");
        }
        // NOTE: findRecoveryId already searches against the normalized s,
        // so no additional parity flip is needed here.

        uint8_t out[65] = {0};
        BN_bn2binpad(r, out, 32);
        BN_bn2binpad(sLow, out + 32, 32);
        out[64] = static_cast<uint8_t>(27 + recid);

        BN_free(sLow); BN_free(order); BN_free(half);
        BN_CTX_free(ctx);
        ECDSA_SIG_free(sig);

        return toHexStr(out, 65);
    }

    static std::string deriveAddress(EC_KEY* key) {
        const EC_GROUP* group = EC_KEY_get0_group(key);
        const EC_POINT* pub = EC_KEY_get0_public_key(key);

        size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                        nullptr, 0, nullptr);
        std::vector<uint8_t> raw(len);
        EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                           raw.data(), len, nullptr);

        std::vector<uint8_t> body(raw.begin() + 1, raw.end());
        auto hash = crypto::keccak256(body);
        return toHexStr(hash.data() + 12, 20);
    }
};

} // namespace amp
