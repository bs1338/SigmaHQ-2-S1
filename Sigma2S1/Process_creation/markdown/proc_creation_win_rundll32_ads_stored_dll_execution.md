# proc_creation_win_rundll32_ads_stored_dll_execution

## Title
Potential Rundll32 Execution With DLL Stored In ADS

## ID
9248c7e1-2bf3-4661-a22c-600a8040b446

## Author
Harjot Singh, '@cyb3rjy0t'

## Date
2023-01-21

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detects execution of rundll32 where the DLL being called is stored in an Alternate Data Stream (ADS).

## References
https://lolbas-project.github.io/lolbas/Binaries/Rundll32

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine RegExp "[Rr][Uu][Nn][Dd][Ll][Ll]32(\\.[Ee][Xx][Ee])? \\S+?\\w:\\S+?:" AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```