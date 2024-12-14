# proc_creation_win_schtasks_delete_all

## Title
Delete All Scheduled Tasks

## ID
220457c1-1c9f-4c2e-afe6-9598926222c1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.impact, attack.t1489

## Description
Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /delete " AND TgtProcCmdLine containsCIS "/tn \*" AND TgtProcCmdLine containsCIS " /f") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```