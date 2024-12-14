# proc_creation_win_lolbin_tracker

## Title
Potential DLL Injection Or Execution Using Tracker.exe

## ID
148431ce-4b70-403d-8525-fcc2993f29ea

## Author
Avneet Singh @v3t0_, oscd.community

## Date
2020-10-18

## Tags
attack.defense-evasion, attack.t1055.001

## Description
Detects potential DLL injection and execution using "Tracker.exe"

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " /d " OR TgtProcCmdLine containsCIS " /c ") AND (TgtProcImagePath endswithCIS "\tracker.exe" OR TgtProcDisplayName = "Tracker")) AND (NOT (TgtProcCmdLine containsCIS " /ERRORREPORT:PROMPT " OR (SrcProcImagePath endswithCIS "\Msbuild\Current\Bin\MSBuild.exe" OR SrcProcImagePath endswithCIS "\Msbuild\Current\Bin\amd64\MSBuild.exe")))))

```