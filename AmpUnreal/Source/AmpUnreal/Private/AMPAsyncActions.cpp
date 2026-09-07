// AMP — Blueprint async action implementations.

#include "AMPAsyncActions.h"
#include "AMPSubsystem.h"
#include "AmpUnreal.h"
#include "AmpCore.h"

#include "Engine/GameInstance.h"
#include "Engine/World.h"
#include "Engine/GameEngine.h"
#include "Kismet/GameplayStatics.h"
#include "TimerManager.h"
#include "Json.h"
#include "Dom/JsonObject.h"

namespace {

FString JsonStrOf(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	FString V;
	return (Obj.IsValid() && Obj->TryGetStringField(Key, V)) ? V : FString();
}

int64 JsonInt64Of(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	if (!Obj.IsValid()) return 0;
	int64 N = 0;
	if (Obj->TryGetNumberField<int64>(Key, N)) return N;
	FString S;
	if (Obj->TryGetStringField(Key, S)) return FCString::Atoi64(*S);
	return 0;
}

double JsonDoubleOf(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	if (!Obj.IsValid()) return 0;
	double D = 0;
	if (Obj->TryGetNumberField(Key, D)) return D;
	FString S;
	if (Obj->TryGetStringField(Key, S)) return FCString::Atod(*S);
	return 0;
}

bool ParseJson(const FString& Raw, TSharedPtr<FJsonObject>& Out)
{
	TSharedRef<TJsonReader<TCHAR>> Reader = TJsonReaderFactory<TCHAR>::Create(Raw);
	return FJsonSerializer::Deserialize(Reader, Out) && Out.IsValid();
}

TSharedPtr<FJsonObject> ParseJsonObject(const FString& Raw)
{
	TSharedPtr<FJsonObject> Obj;
	ParseJson(Raw, Obj);
	return Obj;
}

/** Minimal JSON literal builder — flat string + integer fields. */
FString BuildBody(const TArray<TPair<FString, FString>>& StringFields,
                  const TArray<TPair<FString, int64>>& NumberFields)
{
	FString Out = TEXT("{");
	bool bFirst = true;
	for (const TPair<FString, FString>& Pair : StringFields)
	{
		if (Pair.Value.IsEmpty()) continue;
		if (!bFirst) Out += TEXT(",");
		bFirst = false;
		FString Esc = Pair.Value.Replace(TEXT("\\"), TEXT("\\\\")).Replace(TEXT("\""), TEXT("\\\""));
		Out += FString::Printf(TEXT("\"%s\":\"%s\""), *Pair.Key, *Esc);
	}
	for (const TPair<FString, int64>& Pair : NumberFields)
	{
		if (!bFirst) Out += TEXT(",");
		bFirst = false;
		Out += FString::Printf(TEXT("\"%s\":%lld"), *Pair.Key, static_cast<long long>(Pair.Value));
	}
	Out += TEXT("}");
	return Out;
}

} // namespace

// ── Base machinery ───────────────────────────────────────────────

void UAMPAsyncAction::Activate()
{
	if (!PendingVerb.IsEmpty())
	{
		RunRequest(PendingVerb, PendingPath, PendingBody);
	}
}

UAMPSubsystem* UAMPAsyncAction::ResolveSubsystem()
{
	if (Subsystem.IsValid())
	{
		return Subsystem.Get();
	}

	UGameInstance* GI = nullptr;
	if (UWorld* World = GEngine ? GEngine->GetWorldFromContextObject(WorldCtx.Get(), EGetWorldErrorMode::LogAndReturnNull) : nullptr)
	{
		GI = World->GetGameInstance();
	}
	if (!GI)
	{
		Fail(TEXT("no_world"), TEXT("No valid world context for the AMP subsystem"));
		return nullptr;
	}
	UAMPSubsystem* Sub = GI->GetSubsystem<UAMPSubsystem>();
	if (!Sub)
	{
		Fail(TEXT("no_subsystem"), TEXT("AMP subsystem unavailable"));
		return nullptr;
	}
	Subsystem = Sub;
	return Sub;
}

void UAMPAsyncAction::QueueRequest(const FString& Verb, const FString& Path, const FString& Body)
{
	PendingVerb = Verb;
	PendingPath = Path;
	PendingBody = Body;
}

void UAMPAsyncAction::RunRequest(const FString& Verb, const FString& Path, const FString& Body)
{
	UAMPSubsystem* Sub = ResolveSubsystem();
	if (!Sub) return;

	Sub->SendRequest(Verb, Path, Body,
		[this](bool bOk, int32 StatusCode, const FString& ResponseBody)
		{
			if (!bOk || StatusCode >= 400)
			{
				OnError.Broadcast(MakeError(StatusCode, ResponseBody));
				SetReadyToDestroy();
				return;
			}
			DispatchOk(ResponseBody);
			SetReadyToDestroy();
		});
}

void UAMPAsyncAction::DispatchOk(const FString& RawJson)
{
	// Default: no-op. Nodes with raw-JSON delegates override this.
	UE_LOG(LogAMP, Verbose, TEXT("AMP response: %s"), *RawJson);
}

void UAMPAsyncAction::Fail(const FString& Code, const FString& Message, int32 HttpStatus)
{
	FAMPError Err;
	Err.Code = Code;
	Err.Message = Message;
	Err.HttpStatus = HttpStatus;
	OnError.Broadcast(Err);
	SetReadyToDestroy();
}

FAMPError UAMPAsyncAction::MakeError(int32 StatusCode, const FString& Body)
{
	FAMPError Err;
	Err.HttpStatus = StatusCode;
	if (StatusCode == 0)
	{
		Err.Code = TEXT("network");
		Err.Message = TEXT("Cannot reach the matchmaker");
		return Err;
	}
	TSharedPtr<FJsonObject> Obj = ParseJsonObject(Body);
	if (Obj.IsValid())
	{
		Err.Code = JsonStrOf(Obj, TEXT("code"));
		if (Err.Code.IsEmpty())
		{
			Err.Code = JsonStrOf(Obj, TEXT("error"));
		}
		Err.Message = JsonStrOf(Obj, TEXT("message"));
	}
	if (Err.Code.IsEmpty()) Err.Code = TEXT("http_error");
	if (Err.Message.IsEmpty()) Err.Message = FString::Printf(TEXT("HTTP %d"), StatusCode);
	return Err;
}

// ── Login (challenge → EIP-191 sign → verify) ────────────────────

UAMPLoginAction* UAMPLoginAction::AMPLogin(UObject* WorldContextObject, FString DevPrivateKey)
{
	UAMPLoginAction* Node = NewObject<UAMPLoginAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->DevPrivateKey = DevPrivateKey;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->StartLogin();
	return Node;
}

void UAMPLoginAction::StartLogin()
{
	UAMPSubsystem* Sub = ResolveSubsystem();
	if (!Sub) return;

	if (!DevPrivateKey.IsEmpty() && !Sub->SetDevPrivateKey(DevPrivateKey))
	{
		Fail(TEXT("bad_key"), TEXT("SetDevPrivateKey failed — invalid hex key"));
		return;
	}

	const FAMPSigner* S = Sub->GetSigner();
	if (!S)
	{
		Fail(TEXT("no_signer"), TEXT("No signer — pass DevPrivateKey (dev) or call SetCustomSigner (production)"));
		return;
	}

	const FString Wallet = S->GetAddress();

	// 1. Challenge
	Sub->SendRequest(TEXT("POST"), TEXT("/v1/auth/challenge"),
		BuildBody({{TEXT("wallet"), Wallet}}, {}),
		[this, Sub, Wallet, S](bool bOk, int32 Code, const FString& Body)
		{
			if (!bOk || Code >= 400)
			{
				OnError.Broadcast(MakeError(Code, Body));
				SetReadyToDestroy();
				return;
			}
			const FString Challenge = JsonStrOf(ParseJsonObject(Body), TEXT("challenge"));
			if (Challenge.IsEmpty())
			{
				Fail(TEXT("auth"), TEXT("Server returned no challenge"));
				return;
			}

			// 2. Sign (gasless EIP-191)
			FString Signature, Err;
			if (!S->SignPersonalSign(Challenge, Signature, Err))
			{
				Fail(TEXT("sign"), Err);
				return;
			}

			// 3. Verify
			Sub->SendRequest(TEXT("POST"), TEXT("/v1/auth/verify"),
				BuildBody({{TEXT("wallet"), Wallet}, {TEXT("signature"), Signature}, {TEXT("challenge"), Challenge}}, {}),
				[this, Sub, Wallet](bool bOk2, int32 Code2, const FString& Body2)
				{
					if (!bOk2 || Code2 >= 400)
					{
						OnError.Broadcast(MakeError(Code2, Body2));
						SetReadyToDestroy();
						return;
					}
					const FString Token = JsonStrOf(ParseJsonObject(Body2), TEXT("token"));
					if (Token.IsEmpty())
					{
						Fail(TEXT("auth"), TEXT("Server returned no token"));
						return;
					}
					Sub->SetSession(Wallet, Token);
					Sub->ConnectEvents();

					FAMPPlayer P;
					P.Wallet = Wallet;
					P.Region = TEXT("na");
					P.Language = TEXT("en");
					OnSuccess.Broadcast(P);
					SetReadyToDestroy();
				});
		});
}

// ── Games ────────────────────────────────────────────────────────

UAMPGetGamesAction* UAMPGetGamesAction::AMPGetGames(UObject* WorldContextObject)
{
	UAMPGetGamesAction* Node = NewObject<UAMPGetGamesAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"), TEXT("/v1/games"), FString());
	return Node;
}

void UAMPGetGamesAction::DispatchOk(const FString& RawJson)
{
	TSharedPtr<FJsonObject> Obj = ParseJsonObject(RawJson);
	if (!Obj.IsValid())
	{
		Fail(TEXT("parse"), TEXT("Malformed games response"));
		return;
	}

	TArray<FAMPGameInfo> Games;
	TArray<TSharedPtr<FJsonValue>> RawGames;
	if (Obj->TryGetArrayField(TEXT("games"), RawGames))
	{
		for (const TSharedPtr<FJsonValue>& Gv : RawGames)
		{
			TSharedPtr<FJsonObject> G;
			if (Gv.IsValid() && Gv->TryGetObject(G) && G.IsValid())
			{
				FAMPGameInfo GInfo;
				GInfo.Id = JsonStrOf(G, TEXT("id"));
				GInfo.Name = JsonStrOf(G, TEXT("name"));
				TArray<TSharedPtr<FJsonValue>> RawRules;
				if (G->TryGetArrayField(TEXT("rulesets"), RawRules))
				{
					for (const TSharedPtr<FJsonValue>& Rv : RawRules)
					{
						TSharedPtr<FJsonObject> R;
						if (Rv.IsValid() && Rv->TryGetObject(R) && R.IsValid())
						{
							FAMPRuleset Rs;
							Rs.Id = JsonStrOf(R, TEXT("id"));
							Rs.Name = JsonStrOf(R, TEXT("name"));
							Rs.QueueDepth = static_cast<int32>(JsonInt64Of(R, TEXT("queueDepth")));
							GInfo.Rulesets.Add(Rs);
						}
					}
				}
				Games.Add(GInfo);
			}
		}
	}
	OnSuccess.Broadcast(Games);
	SetReadyToDestroy();
}

// ── Player ───────────────────────────────────────────────────────

UAMPMeAction* UAMPMeAction::AMPMe(UObject* WorldContextObject)
{
	UAMPMeAction* Node = NewObject<UAMPMeAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"), TEXT("/v1/me"), FString());
	return Node;
}

void UAMPMeAction::DispatchOk(const FString& RawJson)
{
	OnSuccess.Broadcast(RawJson);
	SetReadyToDestroy();
}

UAMPGetPlayerAction* UAMPGetPlayerAction::AMPGetPlayer(UObject* WorldContextObject, FString Wallet)
{
	UAMPGetPlayerAction* Node = NewObject<UAMPGetPlayerAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"), FString::Printf(TEXT("/v1/players/%s"), *Wallet), FString());
	return Node;
}

// ── Queue ────────────────────────────────────────────────────────

UAMPJoinQueueAction* UAMPJoinQueueAction::AMPJoinQueue(UObject* WorldContextObject, FString GameId, FString RulesetId)
{
	UAMPJoinQueueAction* Node = NewObject<UAMPJoinQueueAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/queue/join"),
		BuildBody({{TEXT("gameId"), GameId}, {TEXT("rulesetId"), RulesetId}}, {}));
	return Node;
}

UAMPLeaveQueueAction* UAMPLeaveQueueAction::AMPLeaveQueue(UObject* WorldContextObject)
{
	UAMPLeaveQueueAction* Node = NewObject<UAMPLeaveQueueAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/queue/leave"), TEXT("{}"));
	return Node;
}

UAMPQueueStatusAction* UAMPQueueStatusAction::AMPQueueStatus(UObject* WorldContextObject)
{
	UAMPQueueStatusAction* Node = NewObject<UAMPQueueStatusAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"), TEXT("/v1/queue/status"), FString());
	return Node;
}

void UAMPQueueStatusAction::DispatchOk(const FString& RawJson)
{
	TSharedPtr<FJsonObject> Obj = ParseJsonObject(RawJson);
	if (!Obj.IsValid())
	{
		Fail(TEXT("parse"), TEXT("Malformed queue status"));
		return;
	}
	FAMPQueueStatus St;
	St.bQueued = Obj->GetBoolField(TEXT("queued"));
	St.Depth = static_cast<int32>(JsonInt64Of(Obj, TEXT("depth")));
	St.WaitedMs = JsonInt64Of(Obj, TEXT("waitedMs"));
	St.SkillWindow = JsonDoubleOf(Obj, TEXT("skillWindow"));
	OnSuccess.Broadcast(St);
	SetReadyToDestroy();
}

UAMPPlayBotAction* UAMPPlayBotAction::AMPPlayBot(UObject* WorldContextObject)
{
	UAMPPlayBotAction* Node = NewObject<UAMPPlayBotAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/queue/play-bot"), TEXT("{}"));
	return Node;
}

void UAMPPlayBotAction::DispatchOk(const FString& RawJson)
{
	OnSuccess.Broadcast(JsonStrOf(ParseJsonObject(RawJson), TEXT("matchId")));
	SetReadyToDestroy();
}

// ── Wait For Match ───────────────────────────────────────────────

UAMPWaitForMatchAction* UAMPWaitForMatchAction::AMPWaitForMatch(UObject* WorldContextObject, float TimeoutSeconds)
{
	UAMPWaitForMatchAction* Node = NewObject<UAMPWaitForMatchAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->Timeout = TimeoutSeconds;
	Node->RegisterWithGameInstance(WorldContextObject);
	return Node;
}

void UAMPWaitForMatchAction::Activate()
{
	UGameInstance* GI = nullptr;
	if (UWorld* World = GEngine ? GEngine->GetWorldFromContextObject(WorldCtx.Get(), EGetWorldErrorMode::LogAndReturnNull) : nullptr)
	{
		GI = World->GetGameInstance();
	}
	if (!GI)
	{
		FAMPError Err; Err.Code = TEXT("no_world"); Err.Message = TEXT("No world context");
		OnTimeout.Broadcast(Err);
		SetReadyToDestroy();
		return;
	}
	Subsystem = GI->GetSubsystem<UAMPSubsystem>();
	if (!Subsystem.IsValid())
	{
		FAMPError Err; Err.Code = TEXT("no_subsystem"); Err.Message = TEXT("AMP subsystem unavailable");
		OnTimeout.Broadcast(Err);
		SetReadyToDestroy();
		return;
	}

	// WebSocket push
	Subsystem->OnMatchFound.AddDynamic(this, &UAMPWaitForMatchAction::HandleMatchFoundProxy);

	// REST fallback + timeout via the world timer (game thread)
	FTimerManager& Tm = GI->GetTimerManager();
	Tm.SetTimer(PollHandle, FTimerDelegate::CreateUObject(this, &UAMPWaitForMatchAction::CheckOnce), 2.0f, true);
	if (Timeout > 0)
	{
		Tm.SetTimer(TimeoutHandle, FTimerDelegate::CreateUObject(this, &UAMPWaitForMatchAction::TimedOut), Timeout, false);
	}
	CheckOnce(); // immediate check, don't wait 2 s
}

void UAMPWaitForMatchAction::CheckOnce()
{
	if (bDone || !Subsystem.IsValid()) return;
	Subsystem->SendRequest(TEXT("GET"), TEXT("/v1/me"), FString(),
		[this](bool bOk, int32, const FString& Body)
		{
			if (bDone) return;
			const FString LiveId = JsonStrOf(ParseJsonObject(Body), TEXT("liveMatchId"));
			if (!LiveId.IsEmpty())
			{
				FAMPMatchFound M;
				M.MatchId = LiveId;
				Finish(M);
			}
		});
}

void UAMPWaitForMatchAction::Finish(const FAMPMatchFound& Match)
{
	if (bDone) return;
	bDone = true;
	Cleanup();
	OnFound.Broadcast(Match);
	SetReadyToDestroy();
}

void UAMPWaitForMatchAction::TimedOut()
{
	if (bDone) return;
	bDone = true;
	Cleanup();
	FAMPError Err;
	Err.Code = TEXT("timeout");
	Err.Message = FString::Printf(TEXT("No match within %.0f s"), Timeout);
	OnTimeout.Broadcast(Err);
	SetReadyToDestroy();
}

void UAMPWaitForMatchAction::Cleanup()
{
	if (Subsystem.IsValid())
	{
		Subsystem->OnMatchFound.RemoveDynamic(this, &UAMPWaitForMatchAction::HandleMatchFoundProxy);
	}
	if (UGameInstance* GI = GetGameInstance())
	{
		FTimerManager& Tm = GI->GetTimerManager();
		Tm.ClearTimer(PollHandle);
		Tm.ClearTimer(TimeoutHandle);
	}
}

// ── Matches ──────────────────────────────────────────────────────

UAMPGetMatchAction* UAMPGetMatchAction::AMPGetMatch(UObject* WorldContextObject, FString MatchId)
{
	UAMPGetMatchAction* Node = NewObject<UAMPGetMatchAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"), FString::Printf(TEXT("/v1/matches/%s"), *MatchId), FString());
	return Node;
}

UAMPMatchHistoryAction* UAMPMatchHistoryAction::AMPMatchHistory(UObject* WorldContextObject, int32 Limit, int32 Offset)
{
	UAMPMatchHistoryAction* Node = NewObject<UAMPMatchHistoryAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("GET"),
		FString::Printf(TEXT("/v1/matches/history?limit=%d&offset=%d"), Limit, Offset), FString());
	return Node;
}

UAMPReportMatchAction* UAMPReportMatchAction::AMPReportMatch(UObject* WorldContextObject, FString MatchId, EAMPMatchResult Result)
{
	UAMPReportMatchAction* Node = NewObject<UAMPReportMatchAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->MatchId = MatchId;
	Node->Result = Result;
	Node->RegisterWithGameInstance(WorldContextObject);

	const TCHAR* ResultStr = Result == EAMPMatchResult::Win ? TEXT("win")
	                       : Result == EAMPMatchResult::Loss ? TEXT("loss") : TEXT("draw");
	const FString Message = FString::Printf(TEXT("AMP_REPORT:v1:%s:%s"), *MatchId, ResultStr);

	UAMPSubsystem* Sub = Node->ResolveSubsystem();
	if (!Sub) return Node;

	FString Signature, Err;
	if (!Sub->SignPersonalSign(Message, Signature, Err))
	{
		Node->Fail(TEXT("sign"), Err);
		return Node;
	}

	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/matches/%s/report"), *MatchId),
		BuildBody({{TEXT("result"), ResultStr}, {TEXT("signature"), Signature}}, {}));
	return Node;
}

void UAMPReportMatchAction::DispatchOk(const FString& RawJson)
{
	OnSuccess.Broadcast(RawJson);
	SetReadyToDestroy();
}

// ── Parties ──────────────────────────────────────────────────────

UAMPCreatePartyAction* UAMPCreatePartyAction::AMPCreateParty(UObject* WorldContextObject, FString GameId, FString RulesetId)
{
	UAMPCreatePartyAction* Node = NewObject<UAMPCreatePartyAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	// NOTE: party endpoints use snake_case (historical wire format)
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/parties"),
		BuildBody({{TEXT("game_id"), GameId}, {TEXT("ruleset_id"), RulesetId}}, {}));
	return Node;
}

void UAMPCreatePartyAction::DispatchOk(const FString& RawJson)
{
	TSharedPtr<FJsonObject> Obj = ParseJsonObject(RawJson);
	if (!Obj.IsValid())
	{
		Fail(TEXT("parse"), TEXT("Malformed party response"));
		return;
	}
	FAMPPartyCreated P;
	P.PartyId = JsonStrOf(Obj, TEXT("partyId"));
	P.InviteCode = JsonStrOf(Obj, TEXT("inviteCode"));
	P.Leader = JsonStrOf(Obj, TEXT("leader"));
	OnSuccess.Broadcast(P);
	SetReadyToDestroy();
}

UAMPJoinPartyAction* UAMPJoinPartyAction::AMPJoinParty(UObject* WorldContextObject, FString InviteCode)
{
	UAMPJoinPartyAction* Node = NewObject<UAMPJoinPartyAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/parties/join"),
		BuildBody({{TEXT("invite_code"), InviteCode.ToUpper()}}, {}));
	return Node;
}

UAMPLockPartyAction* UAMPLockPartyAction::AMPLockParty(UObject* WorldContextObject, FString PartyId)
{
	UAMPLockPartyAction* Node = NewObject<UAMPLockPartyAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/parties/%s/lock"), *PartyId), TEXT("{}"));
	return Node;
}

UAMPDisbandPartyAction* UAMPDisbandPartyAction::AMPDisbandParty(UObject* WorldContextObject, FString PartyId)
{
	UAMPDisbandPartyAction* Node = NewObject<UAMPDisbandPartyAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/parties/%s/disband"), *PartyId), TEXT("{}"));
	return Node;
}

// Raw passthrough for the string-success nodes
#define AMP_RAW_DISPATCH(Class) \
	void Class::DispatchOk(const FString& RawJson) \
	{ \
		OnSuccess.Broadcast(RawJson); \
		SetReadyToDestroy(); \
	}

AMP_RAW_DISPATCH(UAMPGetPlayerAction)
AMP_RAW_DISPATCH(UAMPJoinQueueAction)
AMP_RAW_DISPATCH(UAMPLeaveQueueAction)
AMP_RAW_DISPATCH(UAMPGetMatchAction)
AMP_RAW_DISPATCH(UAMPMatchHistoryAction)
AMP_RAW_DISPATCH(UAMPJoinPartyAction)
AMP_RAW_DISPATCH(UAMPLockPartyAction)
AMP_RAW_DISPATCH(UAMPDisbandPartyAction)
AMP_RAW_DISPATCH(UAMPMultiRevealAction)
AMP_RAW_DISPATCH(UAMPMultiReportAction)
AMP_RAW_DISPATCH(UAMPMultiClaimAction)
AMP_RAW_DISPATCH(UAMPSubmitExitCertAction)
AMP_RAW_DISPATCH(UAMPCountersignExitCertAction)
AMP_RAW_DISPATCH(UAMPVerifyEscrowAction)

// ── Multiplayer ──────────────────────────────────────────────────

UAMPMultiCommitAction* UAMPMultiCommitAction::AMPMultiCommit(UObject* WorldContextObject, FString GameId, int64 StakeWei, int32 LobbySize)
{
	UAMPMultiCommitAction* Node = NewObject<UAMPMultiCommitAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);

	UAMPSubsystem* Sub = Node->ResolveSubsystem();
	if (!Sub) return Node;
	if (!Sub->IsAuthenticated())
	{
		Node->Fail(TEXT("not_authenticated"), TEXT("Login before Multi Commit"));
		return Node;
	}

	// Generate the salt locally; only keccak256(wallet ‖ stake ‖ salt) goes
	// on the wire until the reveal — nobody can front-run your lobby slot.
	std::string Salt = ampcore::generateSalt();
	std::string CommitHash = ampcore::computeCommitHash(
		std::string(TCHAR_TO_UTF8(*Sub->GetWallet())),
		static_cast<uint64_t>(StakeWei),
		Salt);

	Node->PendingSalt = UTF8_TO_TCHAR(Salt.c_str());

	Node->QueueRequest(TEXT("POST"), TEXT("/v1/multi/commit"),
		BuildBody({{TEXT("gameId"), GameId},
		           {TEXT("commitHash"), UTF8_TO_TCHAR(CommitHash.c_str())}},
		          {{TEXT("stakeWei"), StakeWei}, {TEXT("lobbySize"), static_cast<int64>(LobbySize)}}));
	return Node;
}

void UAMPMultiCommitAction::DispatchOk(const FString& RawJson)
{
	TSharedPtr<FJsonObject> Obj = ParseJsonObject(RawJson);
	if (!Obj.IsValid())
	{
		Fail(TEXT("parse"), TEXT("Malformed commit response"));
		return;
	}
	FAMPMultiCommit C;
	C.bCommitted = Obj->GetBoolField(TEXT("committed"));
	C.CommittedCount = static_cast<int32>(JsonInt64Of(Obj, TEXT("committedCount")));
	C.bReady = Obj->GetBoolField(TEXT("ready"));
	C.Salt = PendingSalt;
	OnSuccess.Broadcast(C);
	SetReadyToDestroy();
}

UAMPMultiRevealAction* UAMPMultiRevealAction::AMPMultiReveal(UObject* WorldContextObject, FString GameId, FString RulesetId, FString Salt)
{
	UAMPMultiRevealAction* Node = NewObject<UAMPMultiRevealAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), TEXT("/v1/multi/reveal"),
		BuildBody({{TEXT("gameId"), GameId}, {TEXT("rulesetId"), RulesetId}, {TEXT("salt"), Salt}}, {}));
	return Node;
}

UAMPMultiReportAction* UAMPMultiReportAction::AMPMultiReport(
	UObject* WorldContextObject, FString MatchId, TArray<FString> RankedWallets,
	FString TranscriptHash, int64 SessionNonce)
{
	UAMPMultiReportAction* Node = NewObject<UAMPMultiReportAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);

	UAMPSubsystem* Sub = Node->ResolveSubsystem();
	if (!Sub) return Node;

	// Sign the ladder (EIP-712, gasless), then POST.
	FString Signature, Err;
	if (!Sub->SignLadderReport(MatchId, RankedWallets, TranscriptHash, SessionNonce, Signature, Err))
	{
		Node->Fail(TEXT("sign"), Err);
		return Node;
	}

	// ranked: [[wallet, place], …] — best-first
	FString RankedJson = TEXT("[");
	for (int32 i = 0; i < RankedWallets.Num(); i++)
	{
		if (i) RankedJson += TEXT(",");
		RankedJson += FString::Printf(TEXT("[\"%s\",%d]"), *RankedWallets[i], i + 1);
	}
	RankedJson += TEXT("]");

	const FString Body = FString::Printf(
		TEXT("{\"ranked\":%s,\"transcriptHash\":\"%s\",\"sessionNonce\":%lld,\"signature\":\"%s\"}"),
		*RankedJson, *TranscriptHash, static_cast<long long>(SessionNonce), *Signature);

	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/multi/%s/report"), *MatchId), Body);
	return Node;
}

UAMPMultiClaimAction* UAMPMultiClaimAction::AMPMultiClaim(UObject* WorldContextObject, FString MatchId)
{
	UAMPMultiClaimAction* Node = NewObject<UAMPMultiClaimAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/multi/%s/claim"), *MatchId), TEXT("{}"));
	return Node;
}

// ── Exit certificates ────────────────────────────────────────────

UAMPSubmitExitCertAction* UAMPSubmitExitCertAction::AMPSubmitExitCert(
	UObject* WorldContextObject, FString MatchId, int32 Rank, int64 ExitFrame, FString StateHash)
{
	UAMPSubmitExitCertAction* Node = NewObject<UAMPSubmitExitCertAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);

	UAMPSubsystem* Sub = Node->ResolveSubsystem();
	if (!Sub) return Node;

	FString Signature, Err;
	if (!Sub->SignExitCert(MatchId, Rank, ExitFrame, StateHash, Signature, Err))
	{
		Node->Fail(TEXT("sign"), Err);
		return Node;
	}

	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/multi/%s/exit"), *MatchId),
		BuildBody({{TEXT("stateHash"), StateHash}, {TEXT("signature"), Signature}},
		          {{TEXT("rank"), Rank}, {TEXT("exitFrame"), ExitFrame}}));
	return Node;
}

UAMPCountersignExitCertAction* UAMPCountersignExitCertAction::AMPCountersignExitCert(
	UObject* WorldContextObject, FString MatchId, FString Wallet, FString StateHash)
{
	UAMPCountersignExitCertAction* Node = NewObject<UAMPCountersignExitCertAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/multi/%s/exit/%s"), *MatchId, *Wallet),
		BuildBody({{TEXT("stateHash"), StateHash}}, {}));
	return Node;
}

// ── Escrow ───────────────────────────────────────────────────────

UAMPVerifyEscrowAction* UAMPVerifyEscrowAction::AMPVerifyEscrow(UObject* WorldContextObject, FString MatchId)
{
	UAMPVerifyEscrowAction* Node = NewObject<UAMPVerifyEscrowAction>(WorldContextObject);
	Node->WorldCtx = WorldContextObject;
	Node->RegisterWithGameInstance(WorldContextObject);
	Node->QueueRequest(TEXT("POST"), FString::Printf(TEXT("/v1/matches/%s/escrow/verify"), *MatchId), TEXT("{}"));
	return Node;
}
