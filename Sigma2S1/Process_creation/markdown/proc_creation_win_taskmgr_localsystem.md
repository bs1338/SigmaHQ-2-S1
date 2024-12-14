# proc_creation_win_taskmgr_localsystem

## Title
Taskmgr as LOCAL_SYSTEM

## ID
9fff585c-c33e-4a86-b3cd-39312079a65f

## Author
Florian Roth (Nextron Systems)

## Date
2018-03-18

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\taskmgr.exe" AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI")))

```