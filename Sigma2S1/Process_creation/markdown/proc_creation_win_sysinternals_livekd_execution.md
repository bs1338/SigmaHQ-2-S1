# proc_creation_win_sysinternals_livekd_execution

## Title
Potential Memory Dumping Activity Via LiveKD

## ID
a85f7765-698a-4088-afa0-ecfbf8d01fa4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.defense-evasion

## Description
Detects execution of LiveKD based on PE metadata or image name

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/livekd

## False Positives
Administration and debugging activity (must be investigated)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\livekd.exe" OR TgtProcImagePath endswithCIS "\livekd64.exe"))

```