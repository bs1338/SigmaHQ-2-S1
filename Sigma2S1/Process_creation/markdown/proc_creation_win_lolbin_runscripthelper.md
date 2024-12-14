# proc_creation_win_lolbin_runscripthelper

## Title
Suspicious Runscripthelper.exe

## ID
eca49c87-8a75-4f13-9c73-a5a29e845f03

## Author
Victor Sergeev, oscd.community

## Date
2020-10-09

## Tags
attack.execution, attack.t1059, attack.defense-evasion, attack.t1202

## Description
Detects execution of powershell scripts via Runscripthelper.exe

## References
https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "surfacecheck" AND TgtProcImagePath endswithCIS "\Runscripthelper.exe"))

```