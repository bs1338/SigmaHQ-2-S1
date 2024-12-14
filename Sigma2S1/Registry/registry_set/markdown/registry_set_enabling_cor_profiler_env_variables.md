# registry_set_enabling_cor_profiler_env_variables

## Title
Enabling COR Profiler Environment Variables

## ID
ad89044a-8f49-4673-9a55-cbd88a1b374f

## Author
Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research), Jimmy Bayne (@bohops)

## Date
2020-09-10

## Tags
attack.persistence, attack.privilege-escalation, attack.defense-evasion, attack.t1574.012

## Description
Detects .NET Framework CLR and .NET Core CLR "cor_enable_profiling" and "cor_profiler" variables being set and configured.

## References
https://twitter.com/jamieantisocial/status/1304520651248668673
https://www.slideshare.net/JamieWilliams130/started-from-the-bottom-exploiting-data-sources-to-uncover-attck-behaviors
https://www.sans.org/cyber-security-summit/archives
https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling

## False Positives


## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath endswithCIS "\COR_ENABLE_PROFILING" OR RegistryKeyPath endswithCIS "\COR_PROFILER" OR RegistryKeyPath endswithCIS "\CORECLR_ENABLE_PROFILING") OR RegistryKeyPath containsCIS "\CORECLR_PROFILER_PATH"))

```