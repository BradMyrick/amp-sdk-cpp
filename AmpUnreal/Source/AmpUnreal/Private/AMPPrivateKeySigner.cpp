// AMP — OpenSSL private-key signer implementation.

#include "AMPPrivateKeySigner.h"
#include "AmpUnreal.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#pragma clang diagnostic pop

namespace {

FString BytesToHexSig(const uint8_t* Data, size_t Len)
{
	static const TCHAR* Digits = TEXT("0123456789abcdef");
	FString Out;
	Out.Reserve(static_cast<int32>(Len * 2 + 2));
	Out += TEXT("0x");
	for (size_t i = 0; i < Len; i++)
	{
		Out += Digits[Data[i] >> 4];
		Out += Digits[Data[i] & 0xF];
	}
	return Out;
}

std::string ToStd(const FString& S)
{
	TArray<char> Utf8 = StringCast<ANSICHAR>(*S, S.Len()).Get();
	return std::string(Utf8.GetData(), static_cast<size_t>(Utf8.Num()));
}

} // namespace

TUniquePtr<FAMPPrivateKeySigner> FAMPPrivateKeySigner::Create(const FString& PrivateKeyHex, FString& OutError)
{
	std::string Hex = ToStd(PrivateKeyHex);
	if (Hex.size() >= 2 && Hex[0] == '0' && (Hex[1] == 'x' || Hex[1] == 'X'))
	{
		Hex = Hex.substr(2);
	}
	if (Hex.size() != 64)
	{
		OutError = TEXT("Private key must be 64 hex characters");
		return nullptr;
	}

	BIGNUM* Priv = nullptr;
	if (!BN_hex2bn(&Priv, Hex.c_str()) || BN_is_zero(Priv))
	{
		if (Priv) BN_clear_free(Priv);
		OutError = TEXT("Invalid private key");
		return nullptr;
	}

	EC_KEY* Key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!Key)
	{
		BN_clear_free(Priv);
		OutError = TEXT("secp256k1 unavailable in this OpenSSL build");
		return nullptr;
	}

	if (EC_KEY_set_private_key(Key, Priv) != 1)
	{
		BN_clear_free(Priv);
		EC_KEY_free(Key);
		OutError = TEXT("Private key out of secp256k1 range");
		return nullptr;
	}

	const EC_GROUP* Group = EC_KEY_get0_group(Key);
	EC_POINT* Pub = EC_POINT_new(Group);
	if (!Pub || EC_POINT_mul(Group, Pub, Priv, nullptr, nullptr, nullptr) != 1 ||
		EC_KEY_set_public_key(Key, Pub) != 1)
	{
		if (Pub) EC_POINT_free(Pub);
		BN_clear_free(Priv);
		EC_KEY_free(Key);
		OutError = TEXT("Failed to derive public key");
		return nullptr;
	}
	EC_POINT_free(Pub);
	BN_clear_free(Priv);

	// Address = last 20 bytes of keccak256(uncompressed pubkey minus 0x04)
	size_t PubLen = EC_POINT_point2oct(Group, EC_KEY_get0_public_key(Key),
	                                   POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
	TArray<uint8_t> Raw;
	Raw.SetNum(static_cast<int32>(PubLen));
	EC_POINT_point2oct(Group, EC_KEY_get0_public_key(Key), POINT_CONVERSION_UNCOMPRESSED,
	                   Raw.GetData(), PubLen, nullptr);

	std::vector<uint8_t> Body(Raw.GetData() + 1, Raw.GetData() + PubLen);
	std::vector<uint8_t> Hash = ampcore::keccak256(Body);

	TUniquePtr<FAMPPrivateKeySigner> Signer(new FAMPPrivateKeySigner());
	Signer->Key = Key;
	Signer->Address = BytesToHexSig(Hash.data() + 12, 20);
	return Signer;
}

FAMPPrivateKeySigner::~FAMPPrivateKeySigner()
{
	if (Key)
	{
		EC_KEY_free(static_cast<EC_KEY*>(Key));
	}
}

bool FAMPPrivateKeySigner::SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const
{
	std::vector<uint8_t> Digest = ampcore::eip191Digest(ToStd(Message));
	return SignDigest(Digest.data(), OutSignature, OutError);
}

bool FAMPPrivateKeySigner::SignTypedData(const ampcore::Eip712TypedData& TypedData, FString& OutSignature, FString& OutError) const
{
	std::vector<uint8_t> Digest = ampcore::computeEip712Digest(TypedData);
	return SignDigest(Digest.data(), OutSignature, OutError);
}

namespace {

/// Find the recovery id whose recovered key matches ours (no exceptions).
int FindRecoveryId(const EC_KEY* Key, const uint8_t Hash[32], const BIGNUM* R, const BIGNUM* SLow)
{
	const EC_GROUP* Group = EC_KEY_get0_group(Key);
	BN_CTX* Ctx = BN_CTX_new();

	BIGNUM* X = BN_new();
	BIGNUM* E = BN_new();
	BIGNUM* RInv = BN_new();
	BIGNUM* Order = BN_new();
	EC_GROUP_get_order(Group, Order, Ctx);
	BN_bin2bn(Hash, 32, E);

	EC_POINT* RPoint = EC_POINT_new(Group);
	EC_POINT* SR = EC_POINT_new(Group);
	EC_POINT* EG = EC_POINT_new(Group);
	EC_POINT* Q = EC_POINT_new(Group);

	int Found = -1;
	for (int RecId = 0; RecId < 4 && Found < 0; RecId++)
	{
		BN_copy(X, R);
		if (RecId >= 2 && !BN_uadd(X, X, Order)) continue;

		if (!EC_POINT_set_compressed_coordinates(Group, RPoint, X, RecId & 1, Ctx)) continue;
		if (!EC_POINT_mul(Group, EG, E, nullptr, nullptr, Ctx)) continue;
		if (!EC_POINT_mul(Group, SR, nullptr, RPoint, SLow, Ctx)) continue;
		if (!EC_POINT_invert(Group, EG, Ctx)) continue;
		if (!EC_POINT_add(Group, Q, SR, EG, Ctx)) continue;
		if (!BN_mod_inverse(RInv, R, Order, Ctx)) continue;
		if (!EC_POINT_mul(Group, Q, nullptr, Q, RInv, Ctx)) continue;
		if (!EC_POINT_is_on_curve(Group, Q, Ctx)) continue;
		if (EC_POINT_cmp(Group, Q, EC_KEY_get0_public_key(Key), Ctx) == 0)
		{
			Found = RecId;
		}
	}

	BN_free(X); BN_free(E); BN_free(RInv); BN_free(Order);
	EC_POINT_free(RPoint); EC_POINT_free(SR); EC_POINT_free(EG); EC_POINT_free(Q);
	BN_CTX_free(Ctx);
	return Found;
}

} // namespace

bool FAMPPrivateKeySigner::SignDigest(const uint8_t Digest[32], FString& OutSignature, FString& OutError) const
{
	EC_KEY* Key = static_cast<EC_KEY*>(this->Key);
	ECDSA_SIG* Sig = ECDSA_do_sign(Digest, 32, Key);
	if (!Sig)
	{
		OutError = TEXT("OpenSSL signing failed");
		return false;
	}

	const BIGNUM* R = ECDSA_SIG_get0_r(Sig);
	const BIGNUM* S = ECDSA_SIG_get0_s(Sig);

	// Low-s normalization (EIP-2)
	BN_CTX* Ctx = BN_CTX_new();
	BIGNUM* Order = BN_new();
	BIGNUM* Half = BN_new();
	BIGNUM* SLow = BN_dup(S);
	EC_GROUP_get_order(EC_KEY_get0_group(Key), Order, Ctx);
	BN_rshift1(Half, Order);
	if (BN_cmp(S, Half) > 0)
	{
		BN_sub(SLow, Order, S);
	}

	int RecId = FindRecoveryId(Key, Digest, R, SLow);
	if (RecId < 0)
	{
		BN_free(SLow); BN_free(Order); BN_free(Half);
		BN_CTX_free(Ctx);
		ECDSA_SIG_free(Sig);
		OutError = TEXT("Failed to compute recovery id");
		return false;
	}

	uint8_t Out[65] = {0};
	BN_bn2binpad(R, Out, 32);
	BN_bn2binpad(SLow, Out + 32, 32);
	Out[64] = static_cast<uint8_t>(27 + RecId);

	BN_free(SLow); BN_free(Order); BN_free(Half);
	BN_CTX_free(Ctx);
	ECDSA_SIG_free(Sig);

	OutSignature = BytesToHexSig(Out, 65);
	return true;
}
