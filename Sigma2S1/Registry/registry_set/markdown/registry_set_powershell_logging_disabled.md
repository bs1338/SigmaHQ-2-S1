# registry_set_powershell_logging_disabled

## Title
PowerShell Logging Disabled Via Registry Key Tampering

## ID
fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7

## Author
frack113

## Date
2022-04-02

## Tags
attack.defense-evasion, attack.t1564.001

## Description
Detects changes to the registry for the currently logged-in user. In order to disable PowerShell module logging, script block logging or transcription and script execution logging

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-32---windows-powershell-logging-disabled

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath containsCIS "\Microsoft\Windows\PowerShell\" OR RegistryKeyPath containsCIS "\Microsoft\PowerShellCore\") AND (RegistryKeyPath endswithCIS "\ModuleLogging\EnableModuleLogging" OR RegistryKeyPath endswithCIS "\ScriptBlockLogging\EnableScriptBlockLogging" OR RegistryKeyPath endswithCIS "\ScriptBlockLogging\EnableScriptBlockInvocationLogging" OR RegistryKeyPath endswithCIS "\Transcription\EnableTranscripting" OR RegistryKeyPath endswithCIS "\Transcription\EnableInvocationHeader" OR RegistryKeyPath endswithCIS "\EnableScripts")))

```