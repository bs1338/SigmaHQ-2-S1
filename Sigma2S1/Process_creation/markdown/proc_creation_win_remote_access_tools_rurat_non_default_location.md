# proc_creation_win_remote_access_tools_rurat_non_default_location

## Title
Remote Access Tool - RURAT Execution From Unusual Location

## ID
e01fa958-6893-41d4-ae03-182477c5e77d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-19

## Tags
attack.defense-evasion

## Description
Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')

## References
https://redcanary.com/blog/misbehaving-rats/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\rutserv.exe" OR TgtProcImagePath endswithCIS "\rfusclient.exe") OR TgtProcDisplayName = "Remote Utilities") AND (NOT (TgtProcImagePath startswithCIS "C:\Program Files\Remote Utilities" OR TgtProcImagePath startswithCIS "C:\Program Files (x86)\Remote Utilities"))))

```