// AMP — signer abstraction for Unreal.
//
// Two paths, matching every AMP SDK:
//   1. Self-custody: implement FAMPSigner and bridge to your wallet
//      plugin / platform wallet (console, mobile, extension).
//   2. Dev & dedicated servers: FAMPPrivateKeySigner (OpenSSL).

#pragma once

#include "CoreMinimal.h"

// Forward-declared to keep this Public header independent of the
// vendored core (Private/AmpCore).
namespace ampcore { struct Eip712TypedData; }

/**
 * Abstract signer. Implement this to connect a real wallet.
 * All methods are exception-free and safe to call on the game thread.
 */
class FAMPSigner
{
public:
	virtual ~FAMPSigner() = default;

	/** Checksummed address (0x…) this signer controls. */
	virtual FString GetAddress() const = 0;

	/**
	 * Sign an EIP-191 personal message.
	 * @param Message    UTF-8 message string.
	 * @param OutSignature 65-byte r‖s‖v hex (0x + 130 chars), v ∈ {27,28}.
	 * @param OutError   Human-readable failure reason when returning false.
	 */
	virtual bool SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const = 0;

	/**
	 * Sign EIP-712 typed data (built by AmpCore::buildLadderTypedData).
	 * @param OutSignature 65-byte r‖s‖v hex (0x + 130 chars).
	 */
	virtual bool SignTypedData(const ampcore::Eip712TypedData& TypedData, FString& OutSignature, FString& OutError) const = 0;
};
