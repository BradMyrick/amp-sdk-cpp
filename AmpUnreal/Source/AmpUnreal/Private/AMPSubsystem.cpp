// UAMPSubsystem — REST, WebSocket, signing, and event dispatch.

#include "AMPSubsystem.h"
#include "AmpUnreal.h"
#include "AMPPrivateKeySigner.h"
#include "AmpCoreBridge.h"

#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"
#include "WebSocketsModule.h"
#include "IWebSocket.h"
#include "Json.h"
#include "Async/Async.h"
#include "TimerManager.h"
#include "Engine/GameInstance.h"

namespace {

/** Extract a string field from a JSON object. */
FString JsonStr(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	FString V;
	return (Obj.IsValid() && Obj->TryGetStringField(Key, V)) ? V : FString();
}

/** Extract an int64 from either a number or a numeric string field. */
int64 JsonInt64(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	if (!Obj.IsValid()) return 0;
	int64 N = 0;
	if (Obj->TryGetNumberField(Key, N)) return N;
	FString S;
	if (Obj->TryGetStringField(Key, S)) return FCString::Atoi64(*S);
	return 0;
}

double JsonDouble(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Key)
{
	if (!Obj.IsValid()) return 0;
	double D = 0;
	if (Obj->TryGetNumberField(Key, D)) return D;
	FString S;
	if (Obj->TryGetStringField(Key, S)) return FCString::Atod(*S);
	return 0;
}

} // namespace

// ── Subsystem lifecycle ─────────────────────────────────────────

void UAMPSubsystem::Initialize(FSubsystemCollectionBase& Collection)
{
	Super::Initialize(Collection);
	if (ServerUrl.IsEmpty())
	{
		ServerUrl = TEXT("https://amp.playwithamp.xyz");
	}
}

void UAMPSubsystem::Deinitialize()
{
	DisconnectEvents();
	if (UGameInstance* GI = GetGameInstance())
	{
		GI->GetTimerManager().ClearTimer(WsReconnectHandle);
	}
	Signer.Reset();
	Super::Deinitialize();
}

// ── Signer setup ────────────────────────────────────────────────

bool UAMPSubsystem::SetDevPrivateKey(const FString& PrivateKeyHex)
{
	FString Err;
	TUniquePtr<FAMPPrivateKeySigner> NewSigner = FAMPPrivateKeySigner::Create(PrivateKeyHex, Err);
	if (!NewSigner)
	{
		UE_LOG(LogAMP, Error, TEXT("SetDevPrivateKey failed: %s"), *Err);
		return false;
	}
	UE_LOG(LogAMP, Warning,
		TEXT("Dev private key signer active for %s — do NOT ship player keys in clients."),
		*NewSigner->GetAddress());
	Signer = MoveTemp(NewSigner);
	return true;
}

void UAMPSubsystem::SetCustomSigner(TUniquePtr<FAMPSigner> InSigner)
{
	Signer = MoveTemp(InSigner);
}

// ── Signing helpers ─────────────────────────────────────────────

bool UAMPSubsystem::SignPersonalSign(const FString& Message, FString& OutSignature, FString& OutError) const
{
	if (!Signer)
	{
		OutError = TEXT("No signer configured — call SetDevPrivateKey or SetCustomSigner first");
		return false;
	}
	return Signer->SignPersonalSign(Message, OutSignature, OutError);
}

bool UAMPSubsystem::SignLadderReport(
	const FString& MatchId,
	const TArray<FString>& RankedWallets,
	const FString& TranscriptHash,
	int64 SessionNonce,
	FString& OutSignature,
	FString& OutError) const
{
	if (!Signer)
	{
		OutError = TEXT("No signer configured");
		return false;
	}

	// Digest via the engine-free bridge (C ABI — no std types in UE TUs).
	// Keep the UTF-8 conversions alive for the duration of the call.
	TArray<TArray<ANSICHAR>> PlacementBuffers;
	TArray<const char*> PlacementPtrs;
	PlacementBuffers.SetNum(RankedWallets.Num());
	PlacementPtrs.SetNum(RankedWallets.Num());
	for (int32 i = 0; i < RankedWallets.Num(); i++)
	{
		FTCHARToUTF8 Utf8(*RankedWallets[i]);
		PlacementBuffers[i] = TArray<ANSICHAR>(Utf8.Get(), Utf8.Length());
		PlacementPtrs[i] = reinterpret_cast<const char*>(PlacementBuffers[i].GetData());
	}

	uint8_t digest[32];
	amp_ladder_digest(
		static_cast<uint64_t>(ChainId), TCHAR_TO_UTF8(*ContractAddress),
		TCHAR_TO_UTF8(*MatchId), PlacementPtrs.GetData(),
		PlacementPtrs.Num(),
		TCHAR_TO_UTF8(*TranscriptHash), static_cast<uint64_t>(SessionNonce), digest);

	return Signer->SignDigest32(digest, OutSignature, OutError);
}

bool UAMPSubsystem::SignExitCert(
	const FString& MatchId,
	int32 Rank,
	int64 ExitFrame,
	const FString& StateHash,
	FString& OutSignature,
	FString& OutError) const
{
	if (!Signer)
	{
		OutError = TEXT("No signer configured");
		return false;
	}

	char message[512];
	amp_exit_cert_message(TCHAR_TO_UTF8(*MatchId), Rank,
		static_cast<uint64_t>(ExitFrame), TCHAR_TO_UTF8(*StateHash), message, sizeof(message));
	return Signer->SignPersonalSign(UTF8_TO_TCHAR(message), OutSignature, OutError);
}

// ── REST ────────────────────────────────────────────────────────

void UAMPSubsystem::SendRequest(
	const FString& Verb,
	const FString& Path,
	const FString& JsonBody,
	TFunction<void(bool, int32, const FString&)> OnDone)
{
	FHttpModule* Http = &FHttpModule::Get();
	TSharedRef<IHttpRequest, ESPMode::ThreadSafe> Req = Http->CreateRequest();

	FString Url = ServerUrl;
	while (Url.EndsWith(TEXT("/"))) Url.LeftChopInline(1, EAllowShrinking::No);
	Url += Path;

	Req->SetURL(Url);
	Req->SetVerb(Verb);
	Req->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
	Req->SetHeader(TEXT("Accept"), TEXT("application/json"));
	Req->SetHeader(TEXT("User-Agent"), TEXT("AmpUnreal/0.1"));
	if (!Token.IsEmpty())
	{
		Req->SetHeader(TEXT("Authorization"), FString::Printf(TEXT("Bearer %s"), *Token));
	}
	if (!JsonBody.IsEmpty())
	{
		Req->SetContentAsString(JsonBody);
	}
	Req->SetTimeout(30);

	Req->OnProcessRequestComplete().BindLambda(
		[OnDone](FHttpRequestPtr, FHttpResponsePtr Resp, bool bSucceeded)
		{
			// UE HTTP completes on the game thread — safe to dispatch directly.
			if (!bSucceeded || !Resp.IsValid())
			{
				OnDone(false, 0, TEXT("{\"error\":\"network\",\"message\":\"Cannot reach the matchmaker\"}"));
				return;
			}
			OnDone(true, Resp->GetResponseCode(), Resp->GetContentAsString());
		});

	Req->ProcessRequest();
}

void UAMPSubsystem::SetSession(const FString& InWallet, const FString& InToken)
{
	Wallet = InWallet;
	Token = InToken;
}

// ── WebSocket events ────────────────────────────────────────────

void UAMPSubsystem::ConnectEvents()
{
	if (Token.IsEmpty())
	{
		UE_LOG(LogAMP, Warning, TEXT("ConnectEvents: not authenticated — Login first."));
		return;
	}
	if (Ws.IsValid() && (bWsConnected || Ws->IsConnected()))
	{
		return;
	}

	FString Url = ServerUrl;
	while (Url.EndsWith(TEXT("/"))) Url.LeftChopInline(1, EAllowShrinking::No);
	Url = Url.Replace(TEXT("https://"), TEXT("wss://")).Replace(TEXT("http://"), TEXT("ws://"));
	Url += FString::Printf(TEXT("/v1/ws?token=%s"), *Token);

	Ws = FWebSocketsModule::Get().CreateWebSocket(Url, TEXT("wss"));

	Ws->OnConnected().AddLambda([this]()
	{
		AsyncTask(ENamedThreads::GameThread, [this]()
		{
			bWsConnected = true;
			UE_LOG(LogAMP, Log, TEXT("AMP event stream connected (%s)"), *Wallet);
			OnEventsConnected.Broadcast(Wallet);
		});
	});

	Ws->OnMessage().AddLambda([this](const FString& MessageStr)
	{
		// WS messages arrive on a background thread — marshal to game thread.
		AsyncTask(ENamedThreads::GameThread, [this, MessageStr]()
		{
			HandleWsMessage(MessageStr);
		});
	});

	Ws->OnConnectionError().AddLambda([this](const FString& Err)
	{
		AsyncTask(ENamedThreads::GameThread, [this, Err]()
		{
			bWsConnected = false;
			UE_LOG(LogAMP, Warning, TEXT("AMP event stream error: %s"), *Err);
		});
	});

	Ws->OnClosed().AddLambda([this](int32 Code, const FString& Reason, bool bWasClean)
	{
		AsyncTask(ENamedThreads::GameThread, [this, Code, Reason, bWasClean]()
		{
			bWsConnected = false;
			UE_LOG(LogAMP, Log, TEXT("AMP event stream closed (%d %s) clean=%d"),
				Code, *Reason, bWasClean ? 1 : 0);
			OnEventsClosed.Broadcast(Code);

			// Auto-reconnect after 5s unless we're shutting down or logged out.
			if (!Token.IsEmpty())
			{
				if (UGameInstance* GI = GetGameInstance())
				{
					GI->GetTimerManager().SetTimer(WsReconnectHandle, [this]()
					{
						if (!Token.IsEmpty() && !bWsConnected) ConnectEvents();
					}, 5.0f, false);
				}
			}
		});
	});

	Ws->Connect();
}

void UAMPSubsystem::DisconnectEvents()
{
	if (Ws.IsValid())
	{
		bWsConnected = false;
		if (Ws->IsConnected())
		{
			Ws->Close();
		}
		Ws.Reset();
	}
}

void UAMPSubsystem::HandleWsMessage(const FString& MessageStr)
{
	TSharedPtr<FJsonObject> Msg;
	TSharedRef<TJsonReader<TCHAR>> Reader = TJsonReaderFactory<TCHAR>::Create(MessageStr);
	if (!FJsonSerializer::Deserialize(Reader, Msg) || !Msg.IsValid())
	{
		return;
	}

	const FString Type = JsonStr(Msg, TEXT("type"));
	const TSharedPtr<FJsonObject>* DataPtr = nullptr;
	TSharedPtr<FJsonObject> Fallback = Msg;
	if (!Msg->TryGetObjectField(TEXT("data"), DataPtr) || !DataPtr || !(*DataPtr).IsValid())
	{
		DataPtr = &Fallback;
	}
	const TSharedPtr<FJsonObject>& D = *DataPtr;

	if (Type == TEXT("hello"))
	{
		UE_LOG(LogAMP, Log, TEXT("AMP hello: %s"), *JsonStr(D, TEXT("wallet")));
	}
	else if (Type == TEXT("queue_status"))
	{
		FAMPQueueStatus St;
		St.bQueued = D->GetBoolField(TEXT("queued"));
		St.Depth = static_cast<int32>(JsonInt64(D, TEXT("depth")));
		St.WaitedMs = JsonInt64(D, TEXT("waitedMs"));
		St.SkillWindow = JsonDouble(D, TEXT("skillWindow"));
		OnQueueStatus.Broadcast(St);
	}
	else if (Type == TEXT("match_found"))
	{
		FAMPMatchFound M;
		M.MatchId = JsonStr(D, TEXT("matchId"));
		M.GameId = JsonStr(D, TEXT("gameId"));
		M.RulesetId = JsonStr(D, TEXT("rulesetId"));
		M.bBot = D->GetBoolField(TEXT("bot"));
		const TSharedPtr<FJsonObject>* Opp = nullptr;
		if (D->TryGetObjectField(TEXT("opponent"), Opp) && Opp && Opp->IsValid())
		{
			M.OpponentWallet = JsonStr(*Opp, TEXT("wallet"));
			M.OpponentRating = JsonDouble(*Opp, TEXT("rating"));
		}
		M.YourRating = JsonDouble(D, TEXT("yourRating"));
		M.ExpiresAt = JsonStr(D, TEXT("expiresAt"));
		OnMatchFound.Broadcast(M);
	}
	else if (Type == TEXT("match_result"))
	{
		FAMPMatchResult R;
		R.MatchId = JsonStr(D, TEXT("matchId"));
		R.Outcome = JsonStr(D, TEXT("outcome"));
		R.bWon = D->GetBoolField(TEXT("won"));
		const TSharedPtr<FJsonObject>* You = nullptr;
		if (D->TryGetObjectField(TEXT("you"), You) && You && You->IsValid())
		{
			R.RatingBefore = JsonDouble(*You, TEXT("ratingBefore"));
			R.RatingAfter = JsonDouble(*You, TEXT("ratingAfter"));
		}
		OnMatchResult.Broadcast(R);
	}
	else if (Type == TEXT("multi_lobby_formed"))
	{
		FAMPMultiLobbyFormed L;
		L.MatchId = JsonStr(D, TEXT("matchId"));
		L.LobbySize = static_cast<int32>(JsonInt64(D, TEXT("lobbySize")));
		L.StakeWei = JsonInt64(D, TEXT("stakeWei"));
		L.SessionNonce = JsonInt64(D, TEXT("sessionNonce"));
		OnMultiLobbyFormed.Broadcast(L);
	}
	else if (Type == TEXT("multi_result"))
	{
		OnMultiResult.Broadcast(MessageStr);
	}
	else if (Type == TEXT("multi_cancelled"))
	{
		OnMultiCancelled.Broadcast(MessageStr);
	}
	else if (Type == TEXT("match_update"))
	{
		OnMatchUpdate.Broadcast(MessageStr);
	}
}
