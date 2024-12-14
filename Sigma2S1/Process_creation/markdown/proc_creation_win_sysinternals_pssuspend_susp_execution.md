# proc_creation_win_sysinternals_pssuspend_susp_execution

## Title
Sysinternals PsSuspend Suspicious Execution

## ID
4beb6ae0-f85b-41e2-8f18-8668abc8af78

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-23

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects suspicious execution of Sysinternals PsSuspend, where the utility is used to suspend critical processes such as AV or EDR to bypass defenses

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend
https://twitter.com/0gtweet/status/1638069413717975046

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "msmpeng.exe" AND (TgtProcImagePath endswithCIS "\pssuspend.exe" OR TgtProcImagePath endswithCIS "\pssuspend64.exe")))

```