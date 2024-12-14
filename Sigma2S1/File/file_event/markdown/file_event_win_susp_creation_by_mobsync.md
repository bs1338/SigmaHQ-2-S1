# file_event_win_susp_creation_by_mobsync

## Title
Created Files by Microsoft Sync Center

## ID
409f8a98-4496-4aaa-818a-c931c0a8b832

## Author
elhoim

## Date
2022-04-28

## Tags
attack.t1055, attack.t1218, attack.execution, attack.defense-evasion

## Description
This rule detects suspicious files created by Microsoft Sync Center (mobsync)

## References
https://redcanary.com/blog/intelligence-insights-november-2021/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\mobsync.exe" AND (TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe")))

```