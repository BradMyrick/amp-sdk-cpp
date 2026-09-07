// AMP — private-key signer (dev & dedicated servers).
// Thin wrapper over the engine-free AmpCoreBridge: secp256k1 with RFC
// 6979-class deterministic nonces, EIP-2 low-s normalization, recovery id
// by public-key matching — the algorithm shared by all AMP SDKs.
//
// FOR DEVELOPMENT AND DEDICATED SERVERS ONLY. Never ship a player's
// private key in a client binary.

#pragma once

#include "CoreMinimal.h"
#include "AMPSigner.h"

class FAMPPrivateKeySigner final : public FAMPSigner
{
public:
	/** Construct from a 0x-prefixed 64-hex private key. */
	static TUniquePtr<FAMPPrivateKeySigner> Create(const FString& PrivateKeyHex, FString& OutError);

	virtual ~FAMPPrivateKeySigner() override;

	virtual FString GetAddress() const override { return Address; }

	virtual bool SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const override;
	virtual bool SignDigest32(const uint8_t Digest[32], FString& OutSignature, FString& OutError) const override;

private:
	FAMPPrivateKeySigner() = default;

	FString KeyHex;
	FString Address;
};
