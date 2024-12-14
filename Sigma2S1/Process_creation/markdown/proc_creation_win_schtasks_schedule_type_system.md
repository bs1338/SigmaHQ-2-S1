# proc_creation_win_schtasks_schedule_type_system

## Title
Suspicious Schtasks Schedule Type With High Privileges

## ID
7a02e22e-b885-4404-b38b-1ddc7e65258a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-31

## Tags
attack.execution, attack.t1053.005

## Description
Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create

## False Positives
Some installers were seen using this method of creation unfortunately. Filter them in your environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\schtasks.exe" AND (TgtProcCmdLine containsCIS "NT AUT" OR TgtProcCmdLine containsCIS " SYSTEM" OR TgtProcCmdLine containsCIS "HIGHEST") AND (TgtProcCmdLine containsCIS " ONLOGON " OR TgtProcCmdLine containsCIS " ONSTART " OR TgtProcCmdLine containsCIS " ONCE " OR TgtProcCmdLine containsCIS " ONIDLE ")))

```