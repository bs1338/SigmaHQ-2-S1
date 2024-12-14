# proc_creation_win_lolbin_utilityfunctions

## Title
UtilityFunctions.ps1 Proxy Dll

## ID
0403d67d-6227-4ea8-8145-4e72db7da120

## Author
frack113

## Date
2022-05-28

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.

## References
https://lolbas-project.github.io/lolbas/Scripts/UtilityFunctions/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "UtilityFunctions.ps1" OR TgtProcCmdLine containsCIS "RegSnapin "))

```