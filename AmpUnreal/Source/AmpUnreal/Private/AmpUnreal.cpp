// AmpUnreal — module implementation.

#include "AmpUnreal.h"
#include "Modules/ModuleManager.h"

DEFINE_LOG_CATEGORY(LogAMP);

class FAmpUnrealModule : public IModuleInterface
{
public:
	virtual void StartupModule() override
	{
		UE_LOG(LogAMP, Log, TEXT("AmpUnreal started — ranked matchmaking with wallets."));
	}

	virtual void ShutdownModule() override
	{
		UE_LOG(LogAMP, Log, TEXT("AmpUnreal shut down."));
	}
};

IMPLEMENT_MODULE(FAmpUnrealModule, AmpUnreal)
