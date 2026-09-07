// UAMPSubsystem — the AMP hub. Auto-created per GameInstance.
//
// Get it anywhere:  UAMPSubsystem* AMP = GetGameInstance()->GetSubsystem<UAMPSubsystem>();
// or in Blueprint:  GetGameInstanceSubsystem("AMPSubsystem")
//
// Use the Blueprint async nodes (right-click → "AMP …") for all calls;
// this subsystem holds state (session token, wallet, live events).

#pragma once

#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "AMPTypes.h"
#include "AMPSigner.h"
#include "AMPSubsystem.generated.h"

/** Fired on the game thread for every WebSocket push event. */
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMatchFoundDyn, FAMPMatchFound, Match);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMatchResultDyn, FAMPMatchResult, Result);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnQueueStatusDyn, FAMPQueueStatus, Status);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMultiLobbyFormedDyn, FAMPMultiLobbyFormed, Lobby);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMultiResultDyn, const FString&, RawJson);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMultiCancelledDyn, const FString&, RawJson);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMatchUpdateDyn, const FString&, RawJson);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnWsConnectedDyn, const FString&, Wallet);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnWsClosedDyn, int32, StatusCode);

/**
 * The AMP client. One per GameInstance.
 *
 * Configure the server (optional) in DefaultGame.ini:
 *   [/Script/AmpUnreal.AMPSubsystem]
 *   ServerUrl=https://amp.playwithamp.xyz
 */
UCLASS(Config = Game)
class AMPUNREAL_API UAMPSubsystem : public UGameInstanceSubsystem
{
	GENERATED_BODY()

public:
	// ── Config ──────────────────────────────────────────────

	/** Matchmaker base URL. Defaults to the AMP production server. */
	UPROPERTY(Config, EditAnywhere, BlueprintReadOnly, Category = "AMP")
	FString ServerUrl = TEXT("https://amp.playwithamp.xyz");

	/** Fuji chain id — used for EIP-712 ladder signatures. */
	UPROPERTY(Config, EditAnywhere, BlueprintReadOnly, Category = "AMP")
	int64 ChainId = 43113;

	/** Deployed AMPMultiplayer contract for ladder signatures. */
	UPROPERTY(Config, EditAnywhere, BlueprintReadOnly, Category = "AMP")
	FString ContractAddress = TEXT("0xcabf7b626172fE55d54f03c346563671AbcC77f7");

	// ── Session state ───────────────────────────────────────

	UFUNCTION(BlueprintPure, Category = "AMP")
	bool IsAuthenticated() const { return !Token.IsEmpty(); }

	UFUNCTION(BlueprintPure, Category = "AMP")
	const FString& GetWallet() const { return Wallet; }

	// ── Signer setup ────────────────────────────────────────

	/**
	 * Dev / dedicated-server path: sign with a raw private key (OpenSSL).
	 * NEVER ship a player key in a client — production players use a
	 * wallet-backed signer via SetCustomSigner (C++) or the custodial flow.
	 */
	UFUNCTION(BlueprintCallable, Category = "AMP|Setup")
	bool SetDevPrivateKey(const FString& PrivateKeyHex);

	/** Replace the signer (wallet plugin bridge, custodial bridge, …). */
	void SetCustomSigner(TUniquePtr<FAMPSigner> InSigner);

	// ── Requests (used by the Blueprint async nodes) ────────

	/**
	 * Generic REST call. Body may be empty for GET-like semantics.
	 * Callback fires on the game thread. Requires Login() first unless
	 * bPublicOnly (no Authorization header).
	 */
	void SendRequest(
		const FString& Verb,
		const FString& Path,
		const FString& JsonBody,
		TFunction<void(bool bOk, int32 StatusCode, const FString& Body)> OnDone);

	/** Signer accessor (may be null until SetDevPrivateKey/SetCustomSigner). */
	const FAMPSigner* GetSigner() const { return Signer.Get(); }

	/** Sign an arbitrary EIP-191 message with the active signer. */
	bool SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const;

	/** Build + sign the N-player ladder report (EIP-712). */
	bool SignLadderReport(
		const FString& MatchId,
		const TArray<FString>& RankedWallets,
		const FString& TranscriptHash,
		int64 SessionNonce,
		FString& OutSignature,
		FString& OutError) const;

	/** Build + sign an exit certificate (EIP-191). */
	bool SignExitCert(
		const FString& MatchId,
		int32 Rank,
		int64 ExitFrame,
		const FString& StateHash,
		FString& OutSignature,
		FString& OutError) const;

	// ── Live events (WebSocket) ─────────────────────────────

	/** Connect the event stream. Called automatically after Login. */
	void ConnectEvents();

	/** Close the event stream. */
	void DisconnectEvents();

	UFUNCTION(BlueprintPure, Category = "AMP|Events")
	bool AreEventsConnected() const { return bWsConnected; }

	// ── Subsystem lifecycle ─────────────────────────────────

	virtual void Initialize(FSubsystemCollectionBase& Collection) override;
	virtual void Deinitialize() override;

	// ── Blueprint-bindable events ───────────────────────────

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMatchFoundDyn OnMatchFound;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMatchResultDyn OnMatchResult;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnQueueStatusDyn OnQueueStatus;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMultiLobbyFormedDyn OnMultiLobbyFormed;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMultiResultDyn OnMultiResult;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMultiCancelledDyn OnMultiCancelled;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnMatchUpdateDyn OnMatchUpdate;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnWsConnectedDyn OnEventsConnected;

	UPROPERTY(BlueprintAssignable, Category = "AMP|Events")
	FAMPOnWsClosedDyn OnEventsClosed;

private:
	friend class UAMPLoginAction; // sets the session

	void SetSession(const FString& InWallet, const FString& InToken);
	void HandleWsMessage(const FString& Message);

	TUniquePtr<FAMPSigner> Signer;
	FString Wallet;
	FString Token;

	TSharedPtr<class IWebSocket> Ws;
	bool bWsConnected = false;
	FTimerHandle WsReconnectHandle;
};
