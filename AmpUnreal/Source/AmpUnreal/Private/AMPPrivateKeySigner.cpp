// AMP — private-key signer implementation (bridge-backed).

#include "AMPPrivateKeySigner.h"
#include "AmpUnreal.h"
#include "AmpCoreBridge.h"

TUniquePtr<FAMPPrivateKeySigner> FAMPPrivateKeySigner::Create(const FString& PrivateKeyHex, FString& OutError)
{
	const char* addr = amp_address(TCHAR_TO_UTF8(*PrivateKeyHex));
	if (!addr)
	{
		OutError = TEXT("Invalid private key (must be 64 hex chars, secp256k1 range)");
		return nullptr;
	}

	TUniquePtr<FAMPPrivateKeySigner> Signer(new FAMPPrivateKeySigner());
	Signer->KeyHex = PrivateKeyHex;
	Signer->Address = UTF8_TO_TCHAR(addr);
	return Signer;
}

FAMPPrivateKeySigner::~FAMPPrivateKeySigner() = default;

bool FAMPPrivateKeySigner::SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const
{
	char sig[135];
	FTCHARToUTF8 MsgUtf8(*Message);
	const int rc = amp_sign_eip191(TCHAR_TO_UTF8(*KeyHex), MsgUtf8.Get(), sig, sizeof(sig));
	if (rc != 0)
	{
		OutError = rc == 1
			? TEXT("Invalid private key")
			: TEXT("Signing failed");
		return false;
	}
	OutSignature = UTF8_TO_TCHAR(sig);
	return true;
}

bool FAMPPrivateKeySigner::SignDigest32(const uint8_t Digest[32], FString& OutSignature, FString& OutError) const
{
	char sig[135];
	const int rc = amp_sign_digest(TCHAR_TO_UTF8(*KeyHex), Digest, sig, sizeof(sig));
	if (rc != 0)
	{
		OutError = rc == 1
			? TEXT("Invalid private key")
			: TEXT("Signing failed");
		return false;
	}
	OutSignature = UTF8_TO_TCHAR(sig);
	return true;
}
