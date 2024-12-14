# proc_creation_win_renamed_rurat

## Title
Renamed Remote Utilities RAT (RURAT) Execution

## ID
9ef27c24-4903-4192-881a-3adde7ff92a5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-19

## Tags
attack.defense-evasion, attack.collection, attack.command-and-control, attack.discovery, attack.s0592

## Description
Detects execution of renamed Remote Utilities (RURAT) via Product PE header field

## References
https://redcanary.com/blog/misbehaving-rats/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "Remote Utilities" AND (NOT (TgtProcImagePath endswithCIS "\rutserv.exe" OR TgtProcImagePath endswithCIS "\rfusclient.exe"))))

```