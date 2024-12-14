# proc_creation_win_schtasks_delete

## Title
Delete Important Scheduled Task

## ID
dbc1f800-0fe0-4bc0-9c66-292c2abe3f78

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.impact, attack.t1489

## Description
Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\Windows\BitLocker" OR TgtProcCmdLine containsCIS "\Windows\ExploitGuard" OR TgtProcCmdLine containsCIS "\Windows\SystemRestore\SR" OR TgtProcCmdLine containsCIS "\Windows\UpdateOrchestrator\" OR TgtProcCmdLine containsCIS "\Windows\Windows Defender\" OR TgtProcCmdLine containsCIS "\Windows\WindowsBackup\" OR TgtProcCmdLine containsCIS "\Windows\WindowsUpdate\") AND (TgtProcCmdLine containsCIS "/delete" AND TgtProcCmdLine containsCIS "/tn") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```