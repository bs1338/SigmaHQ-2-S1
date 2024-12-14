# registry_set_enabling_turnoffcheck

## Title
Scripted Diagnostics Turn Off Check Enabled - Registry

## ID
7d995e63-ec83-4aa3-89d5-8a17b5c87c86

## Author
Christopher Peacock @securepeacock, SCYTHE @scythe_io

## Date
2022-06-15

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability

## References
https://twitter.com/wdormann/status/1537075968568877057?s=20&t=0lr18OAnmAGoGpma6grLUw

## False Positives
Administrator actions

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\Policies\Microsoft\Windows\ScriptedDiagnostics\TurnOffCheck"))

```