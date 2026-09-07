// AMP — OpenSSL secp256k1 private-key signer (exception-free).
//
// FOR DEVELOPMENT AND DEDICATED SERVERS ONLY. Never ship a player's
// private key in a client binary — use a wallet-backed FAMPSigner
// implementation or the custodial flow for production players.
//
// Ported from amp-sdk-cpp's PrivateKeySigner: EIP-2 low-s normalization,
// recovery id found by public-key matching, cast-verified vectors.

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
	virtual bool SignTypedData(const ampcore::Eip712TypedData& TypedData, FString& OutSignature, FString& OutError) const override;

private:
	FAMPPrivateKeySigner() = default;

	bool SignDigest(const uint8_t Digest[32], FString& OutSignature, FString& OutError) const;

	void* Key = nullptr;          // EC_KEY* — void* to keep OpenSSL out of headers
	FString Address;
};
