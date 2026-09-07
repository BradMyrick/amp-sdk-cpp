// AmpUnreal — public module header.

#pragma once

#include "CoreMinimal.h"
#include "Modules/ModuleManager.h"

#ifdef AMPUNREAL_EXPORTS
#define AMPUNREAL_API DLLEXPORT
#else
#define AMPUNREAL_API DLLIMPORT
#endif

AMPUNREAL_API DECLARE_LOG_CATEGORY_EXTERN(LogAMP, Log, All);
