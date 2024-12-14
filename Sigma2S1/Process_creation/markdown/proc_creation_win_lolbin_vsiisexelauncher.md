# proc_creation_win_lolbin_vsiisexelauncher

## Title
Use of VSIISExeLauncher.exe

## ID
18749301-f1c5-4efc-a4c3-276ff1f5b6f8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-09

## Tags
attack.defense-evasion, attack.t1127

## Description
The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/VSIISExeLauncher/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -p " OR TgtProcCmdLine containsCIS " -a ") AND TgtProcImagePath endswithCIS "\VSIISExeLauncher.exe"))

```