# proc_creation_win_lolbin_unregmp2

## Title
Lolbin Unregmp2.exe Use As Proxy

## ID
727454c0-d851-48b0-8b89-385611ab0704

## Author
frack113

## Date
2022-12-29

## Tags
attack.defense-evasion, attack.t1218

## Description
Detect usage of the "unregmp2.exe" binary as a proxy to launch a custom version of "wmpnscfg.exe"

## References
https://lolbas-project.github.io/lolbas/Binaries/Unregmp2/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -HideWMP" OR TgtProcCmdLine containsCIS " /HideWMP" OR TgtProcCmdLine containsCIS " â€“HideWMP" OR TgtProcCmdLine containsCIS " â€”HideWMP" OR TgtProcCmdLine containsCIS " â€•HideWMP") AND TgtProcImagePath endswithCIS "\unregmp2.exe"))

```