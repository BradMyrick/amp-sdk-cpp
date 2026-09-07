// AMP — Blueprint-exposed types. Mirrors the server's wire shapes.

#pragma once

#include "CoreMinimal.h"
#include "AMPTypes.generated.h"

/** Result of a 1v1 match report. */
UENUM(BlueprintType)
enum class EAMPMatchResult : uint8
{
	Win,
	Loss,
	Draw
};

/** A player identity. */
USTRUCT(BlueprintType)
struct FAMPPlayer
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Wallet;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Region;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Language;
};

/** A queue ruleset (e.g. "Ranked 1v1 — free"). */
USTRUCT(BlueprintType)
struct FAMPRuleset
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Id;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Name;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 QueueDepth = 0;
};

/** A registered game with its rulesets. */
USTRUCT(BlueprintType)
struct FAMPGameInfo
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Id;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Name;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	TArray<FAMPRuleset> Rulesets;
};

/** Live queue status while waiting. */
USTRUCT(BlueprintType)
struct FAMPQueueStatus
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	bool bQueued = false;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 Depth = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int64 WaitedMs = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double SkillWindow = 0.0;
};

/** Pushed when the matchmaker assigns you an opponent. */
USTRUCT(BlueprintType)
struct FAMPMatchFound
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString MatchId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString GameId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString RulesetId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	bool bBot = false;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString OpponentWallet;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double OpponentRating = 0.0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double YourRating = 0.0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString ExpiresAt;
};

/** Result payload after a settled match. */
USTRUCT(BlueprintType)
struct FAMPMatchResult
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString MatchId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Outcome;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	bool bWon = false;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double RatingBefore = 0.0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double RatingAfter = 0.0;
};

/** A multiplayer lobby assignment (N-player). */
USTRUCT(BlueprintType)
struct FAMPMultiLobbyFormed
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString MatchId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 LobbySize = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int64 StakeWei = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int64 SessionNonce = 0;
};

/** Result of multiCommit — keep the Salt for the reveal phase. */
USTRUCT(BlueprintType)
struct FAMPMultiCommit
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	bool bCommitted = false;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 CommittedCount = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	bool bReady = false;

	/** Keep this — multiReveal needs it. */
	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Salt;
};

/** Party creation result. */
USTRUCT(BlueprintType)
struct FAMPPartyCreated
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString PartyId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString InviteCode;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Leader;
};

/** A player's Glicko-2 rating in a game/ruleset. */
USTRUCT(BlueprintType)
struct FAMPRating
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString GameId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString RulesetId;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double Rating = 1500.0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	double Deviation = 350.0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 Wins = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 Losses = 0;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 Draws = 0;
};

/** Error detail passed on failure pins. */
USTRUCT(BlueprintType)
struct FAMPError
{
	GENERATED_BODY()

	/** Machine-readable code ("http_error", "network", "not_authenticated"). */
	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Code;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	FString Message;

	UPROPERTY(BlueprintReadOnly, Category = "AMP")
	int32 HttpStatus = 0;
};
