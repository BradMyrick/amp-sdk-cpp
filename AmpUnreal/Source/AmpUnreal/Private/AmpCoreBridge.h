/**
 * AmpCoreBridge — C-ABI bridge between the UE layer and the vendored,
 * engine-free protocol core (+ OpenSSL signing).
 *
 * UE 5.8's CoreMinimal no longer exposes std:: types in module TUs, and
 * OpenSSL's headers collide with engine symbols — so NOTHING in this
 * header may include UE or std types. All functions are extern "C",
 * return error codes, and write into caller-provided buffers.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

extern "C" {

/// Address (0x + 40 hex, lowercase) for a private key, or null on error.
/// Result is thread-local — copy before the next call.
const char* amp_address(const char* private_key_hex);

/// 0 on success; nonzero on bad key/signature failure. out_sig must hold
/// 135 bytes ("0x" + 130 hex). EIP-191 over UTF-8 message bytes.
int amp_sign_eip191(const char* private_key_hex, const char* message_utf8,
                    char* out_sig, size_t sig_cap);

/// 0 on success. Signs a raw 32-byte digest (EIP-712 path).
int amp_sign_digest(const char* private_key_hex, const uint8_t digest[32],
                    char* out_sig, size_t sig_cap);

/// EIP-191 digest of a UTF-8 message (32 bytes into out_digest).
void amp_eip191_digest(const char* message_utf8, uint8_t out_digest[32]);

/// Commit-reveal hash into out_hash (67 bytes, "0x"+64 hex, NUL-terminated).
void amp_commit_hash(const char* wallet, uint64_t stake_wei, const char* salt,
                     char* out_hash, size_t hash_cap);

/// Random 32-byte salt as 0x-hex into out_salt (67 bytes).
void amp_generate_salt(char* out_salt, size_t salt_cap);

/// EIP-712 MultiplayerLadder digest (32 bytes into out_digest).
/// Contract typehash: gameId is bytes32 (value 1).
void amp_ladder_digest(uint64_t chain_id, const char* contract_address,
                       const char* match_id, const char* const* ranked_wallets,
                       int wallet_count, const char* transcript_hash,
                       uint64_t session_nonce, uint8_t out_digest[32]);

/// Exit-certificate message into out_message (512 bytes).
void amp_exit_cert_message(const char* match_id, int rank, uint64_t exit_frame,
                           const char* state_hash, char* out_message, size_t message_cap);

/// Report message ("AMP_REPORT:v1:{id}:{result}") into out_message (256 bytes).
void amp_report_message(const char* match_id, const char* result,
                        char* out_message, size_t message_cap);

} // extern "C"
