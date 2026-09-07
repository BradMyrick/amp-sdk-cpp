// AmpUnreal — Build.cs
// UE5.1+ runtime module. HTTP/WebSockets for transport (respects platform
// proxies and certificates), OpenSSL for dev/server-side signing.

using UnrealBuildTool;

public class AmpUnreal : ModuleRules
{
	public AmpUnreal(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

		PublicDependencyModuleNames.AddRange(new string[]
		{
			"Core",
			"CoreUObject",
			"Engine"
		});

		PrivateDependencyModuleNames.AddRange(new string[]
		{
			"HTTP",
			"WebSockets",
			"Json",
			"JsonUtilities",
			"OpenSSL"
		});

		// Vendored, engine-free protocol core (see Private/AmpCore).
		// Compiled with UE's -fno-exceptions -fno-rtti flags and validated
		// against cross-SDK golden vectors — do not add engine types here.
		PrivateIncludePaths.Add("Private/AmpCore");
	}
}
