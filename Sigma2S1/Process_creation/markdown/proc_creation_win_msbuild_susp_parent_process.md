# proc_creation_win_msbuild_susp_parent_process

## Title
Suspicious Msbuild Execution By Uncommon Parent Process

## ID
33be4333-2c6b-44f4-ae28-102cdbde0a31

## Author
frack113

## Date
2022-11-17

## Tags
attack.defense-evasion

## Description
Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process

## References
https://app.any.run/tasks/abdf586e-df0c-4d39-89a7-06bf24913401/
https://www.echotrail.io/insights/search/msbuild.exe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\MSBuild.exe" AND (NOT (SrcProcImagePath endswithCIS "\devenv.exe" OR SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\msbuild.exe" OR SrcProcImagePath endswithCIS "\python.exe" OR SrcProcImagePath endswithCIS "\explorer.exe" OR SrcProcImagePath endswithCIS "\nuget.exe"))))

```