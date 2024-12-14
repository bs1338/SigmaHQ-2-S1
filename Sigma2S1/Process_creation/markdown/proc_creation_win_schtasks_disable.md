# proc_creation_win_schtasks_disable

## Title
Disable Important Scheduled Task

## ID
9ac94dc8-9042-493c-ba45-3b5e7c86b980

## Author
frack113, Nasreddine Bencherchali (Nextron Systems), X__Junior

## Date
2021-12-26

## Tags
attack.impact, attack.t1489

## Description
Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-8---windows---disable-the-sr-scheduled-task
https://twitter.com/MichalKoczwara/status/1553634816016498688
https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\Windows\BitLocker" OR TgtProcCmdLine containsCIS "\Windows\ExploitGuard" OR TgtProcCmdLine containsCIS "\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" OR TgtProcCmdLine containsCIS "\Windows\SystemRestore\SR" OR TgtProcCmdLine containsCIS "\Windows\UpdateOrchestrator\" OR TgtProcCmdLine containsCIS "\Windows\Windows Defender\" OR TgtProcCmdLine containsCIS "\Windows\WindowsBackup\" OR TgtProcCmdLine containsCIS "\Windows\WindowsUpdate\") AND (TgtProcCmdLine containsCIS "/Change" AND TgtProcCmdLine containsCIS "/TN" AND TgtProcCmdLine containsCIS "/disable") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```