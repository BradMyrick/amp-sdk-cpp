// AMP — Blueprint async nodes. Every call is non-blocking with
// OnSuccess / OnError exec pins; responses are typed where it matters
// (matches, games, parties, commits) and raw JSON for the long tail.
//
// Right-click in any Blueprint graph → "AMP …"

#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintAsyncActionBase.h"
#include "AMPTypes.h"
#include "AMPAsyncActions.generated.h"

class UAMPSubsystem;

/** Generic success: raw response JSON. */
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnStringOk, const FString&, RawJson);
/** Generic typed payloads. */
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnPlayerOk, const FAMPPlayer&, Player);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnGamesOk, const TArray<FAMPGameInfo>&, Games);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMatchFoundOk, const FAMPMatchFound&, Match);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnQueueStatusOk, const FAMPQueueStatus&, Status);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnPartyCreatedOk, const FAMPPartyCreated&, Party);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMultiCommitOk, const FAMPMultiCommit&, Commit);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnMatchIdOk, const FString&, MatchId);
/** Errors. */
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAMPOnFail, const FAMPError&, Error);

/**
 * Shared machinery: resolve the subsystem, run one REST request,
 * dispatch typed or raw results. Subsystems persist across levels,
 * so we reference the GameInstance weakly.
 */
UCLASS(Abstract)
class AMPUNREAL_API UAMPAsyncAction : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnFail OnError;

	virtual void Activate() override;

protected:
	/** Resolve the subsystem from the world context. Returns nullptr + fires OnError when unavailable. */
	UAMPSubsystem* ResolveSubsystem();

	/** Queue a REST call; fired from Activate(). */
	void QueueRequest(const FString& Verb, const FString& Path, const FString& Body);

	/** Run a request and route the raw response. */
	void RunRequest(const FString& Verb, const FString& Path, const FString& Body);

	/** Override to dispatch typed results; default broadcasts raw JSON. */
	virtual void DispatchOk(const FString& RawJson);

	void BroadcastRaw(const FString& RawJson);

	void Fail(const FString& Code, const FString& Message, int32 HttpStatus = 0);

	/** Extract "error"/"message" from a failure body. */
	static FAMPError MakeError(int32 StatusCode, const FString& Body);

	UPROPERTY(Transient)
	TWeakObjectPtr<UAMPSubsystem> Subsystem;

	UPROPERTY(Transient)
	TWeakObjectPtr<UObject> WorldCtx;

	FString PendingVerb, PendingPath, PendingBody;
};

// ── Auth ─────────────────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Login"))
class UAMPLoginAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnPlayerOk OnSuccess;

	/** One gasless EIP-191 signature — the player never pays gas. */
	UFUNCTION(BlueprintCallable, Category = "AMP", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPLoginAction* AMPLogin(UObject* WorldContextObject, FString DevPrivateKey);

	/** Runs the challenge → sign → verify flow; call from the factory. */
	void StartLogin();

protected:
	FString DevPrivateKey;
};

// ── Games & player ───────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Get Games"))
class UAMPGetGamesAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnGamesOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPGetGamesAction* AMPGetGames(UObject* WorldContextObject);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Me"))
class UAMPMeAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMeAction* AMPMe(UObject* WorldContextObject);

protected:
	virtual void DispatchOk(const FString& RawJson) override { OnSuccess.Broadcast(RawJson); }
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Get Player"))
class UAMPGetPlayerAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPGetPlayerAction* AMPGetPlayer(UObject* WorldContextObject, FString Wallet);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString Wallet;
};

// ── Queue ────────────────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Join Queue"))
class UAMPJoinQueueAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Queue", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPJoinQueueAction* AMPJoinQueue(UObject* WorldContextObject, FString GameId, FString RulesetId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString GameId, RulesetId;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Leave Queue"))
class UAMPLeaveQueueAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Queue", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPLeaveQueueAction* AMPLeaveQueue(UObject* WorldContextObject);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Queue Status"))
class UAMPQueueStatusAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnQueueStatusOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Queue", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPQueueStatusAction* AMPQueueStatus(UObject* WorldContextObject);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Play Bot"))
class UAMPPlayBotAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnMatchIdOk OnSuccess;

	/** Skip the queue — instant practice match against the house bot. */
	UFUNCTION(BlueprintCallable, Category = "AMP|Queue", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPPlayBotAction* AMPPlayBot(UObject* WorldContextObject);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Wait For Match"))
class UAMPWaitForMatchAction : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnMatchFoundOk OnFound;

	UPROPERTY(BlueprintAssignable)
	FAMPOnFail OnTimeout;

	/**
	 * Wait for a match assignment after joining a queue.
	 * Fires OnFound (WebSocket push with REST fallback) or OnTimeout.
	 * TimeoutSeconds <= 0 waits forever.
	 */
	UFUNCTION(BlueprintCallable, Category = "AMP|Queue", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPWaitForMatchAction* AMPWaitForMatch(UObject* WorldContextObject, float TimeoutSeconds = 30.f);

	virtual void Activate() override;

private:
	/** WS push proxy (dynamic delegates need UFUNCTION handlers). */
	UFUNCTION()
	void HandleMatchFoundProxy(FAMPMatchFound Match) { Finish(Match); }

	void CheckOnce();
	void Finish(const FAMPMatchFound& Match);
	void TimedOut();
	void Cleanup();

	float Timeout = 30.f;
	FTimerHandle PollHandle;
	FTimerHandle TimeoutHandle;
	bool bDone = false;
	TWeakObjectPtr<UAMPSubsystem> Subsystem;
	TWeakObjectPtr<UObject> WorldCtx;
};

// ── Matches (1v1) ────────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Get Match"))
class UAMPGetMatchAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Match", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPGetMatchAction* AMPGetMatch(UObject* WorldContextObject, FString MatchId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Match History"))
class UAMPMatchHistoryAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Match", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMatchHistoryAction* AMPMatchHistory(UObject* WorldContextObject, int32 Limit = 20, int32 Offset = 0);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	int32 Limit = 20, Offset = 0;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Report Match"))
class UAMPReportMatchAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	/** Report your 1v1 result — auto-signs EIP-191 (gasless). */
	UFUNCTION(BlueprintCallable, Category = "AMP|Match", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPReportMatchAction* AMPReportMatch(UObject* WorldContextObject, FString MatchId, EAMPMatchResult Result);

protected:
	virtual void DispatchOk(const FString& RawJson) override { OnSuccess.Broadcast(RawJson); }
	FString MatchId;
	EAMPMatchResult Result = EAMPMatchResult::Win;
};

// ── Parties ──────────────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Create Party"))
class UAMPCreatePartyAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnPartyCreatedOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Party", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPCreatePartyAction* AMPCreateParty(UObject* WorldContextObject, FString GameId, FString RulesetId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString GameId, RulesetId;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Join Party"))
class UAMPJoinPartyAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Party", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPJoinPartyAction* AMPJoinParty(UObject* WorldContextObject, FString InviteCode);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString InviteCode;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Lock Party"))
class UAMPLockPartyAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Party", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPLockPartyAction* AMPLockParty(UObject* WorldContextObject, FString PartyId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString PartyId;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Disband Party"))
class UAMPDisbandPartyAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Party", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPDisbandPartyAction* AMPDisbandParty(UObject* WorldContextObject, FString PartyId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString PartyId;
};

// ── Multiplayer (N-player FFA) ───────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Multi Commit"))
class UAMPMultiCommitAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnMultiCommitOk OnSuccess;

	/**
	 * Commit into the FFA lobby queue (commit-reveal anti-collusion).
	 * The salt is generated internally and returned — pass it to AMP Multi Reveal.
	 */
	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMultiCommitAction* AMPMultiCommit(UObject* WorldContextObject, FString GameId, int64 StakeWei = 0, int32 LobbySize = 4);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString GameId;
	int64 StakeWei = 0;
	int32 LobbySize = 4;
	/** Generated at queue time, returned in the typed result. */
	FString PendingSalt;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Multi Reveal"))
class UAMPMultiRevealAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMultiRevealAction* AMPMultiReveal(UObject* WorldContextObject, FString GameId, FString RulesetId, FString Salt);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString GameId, RulesetId, Salt;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Multi Report"))
class UAMPMultiReportAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	/**
	 * Submit the final ladder, best-first. Auto-signs EIP-712 (gasless).
	 * A quorum of concordant ladders settles the match.
	 */
	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMultiReportAction* AMPMultiReport(
		UObject* WorldContextObject,
		FString MatchId,
		TArray<FString> RankedWallets,
		FString TranscriptHash,
		int64 SessionNonce);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId, TranscriptHash;
	TArray<FString> RankedWallets;
	int64 SessionNonce = 0;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Multi Claim"))
class UAMPMultiClaimAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPMultiClaimAction* AMPMultiClaim(UObject* WorldContextObject, FString MatchId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId;
};

// ── Exit certificates (death certs) ──────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Submit Exit Cert"))
class UAMPSubmitExitCertAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	/**
	 * When your player is eliminated: sign your rank + state hash and
	 * disconnect. Auto-signs EIP-191 — unlocks your reporting bond.
	 */
	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPSubmitExitCertAction* AMPSubmitExitCert(
		UObject* WorldContextObject, FString MatchId, int32 Rank, int64 ExitFrame, FString StateHash);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId, StateHash;
	int32 Rank = 0;
	int64 ExitFrame = 0;
};

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Countersign Exit Cert"))
class UAMPCountersignExitCertAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	/** As a survivor, verify an eliminated player's state hash. */
	UFUNCTION(BlueprintCallable, Category = "AMP|Multi", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPCountersignExitCertAction* AMPCountersignExitCert(
		UObject* WorldContextObject, FString MatchId, FString Wallet, FString StateHash);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId, Wallet, StateHash;
};

// ── Staked 1v1 escrow ────────────────────────────────────────────

UCLASS(MinimalAPI, meta = (DisplayName = "AMP Verify Escrow"))
class UAMPVerifyEscrowAction : public UAMPAsyncAction
{
	GENERATED_BODY()
public:
	UPROPERTY(BlueprintAssignable)
	FAMPOnStringOk OnSuccess;

	/** Verify on-chain escrow for a staked 1v1 (participant only). */
	UFUNCTION(BlueprintCallable, Category = "AMP|Match", Meta = (BlueprintInternalEventOnly = "true", WorldContext = "WorldContextObject"))
	static UAMPVerifyEscrowAction* AMPVerifyEscrow(UObject* WorldContextObject, FString MatchId);

protected:
	virtual void DispatchOk(const FString& RawJson) override;
	FString MatchId;
};
