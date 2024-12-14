# proc_creation_win_kd_execution

## Title
Windows Kernel Debugger Execution

## ID
27ee9438-90dc-4bef-904b-d3ef927f5e7e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects execution of the Windows Kernel Debugger "kd.exe".

## References
Internal Research

## False Positives
Rare occasions of legitimate cases where kernel debugging is necessary in production. Investigation is required

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\kd.exe")

```