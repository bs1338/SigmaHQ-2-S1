# proc_creation_win_schtasks_schedule_type

## Title
Suspicious Schtasks Schedule Types

## ID
24c8392b-aa3c-46b7-a545-43f71657fe98

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-09

## Tags
attack.execution, attack.t1053.005

## Description
Detects scheduled task creations or modification on a suspicious schedule type

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html

## False Positives
Legitimate processes that run at logon. Filter according to your environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\schtasks.exe" AND (TgtProcCmdLine containsCIS " ONLOGON " OR TgtProcCmdLine containsCIS " ONSTART " OR TgtProcCmdLine containsCIS " ONCE " OR TgtProcCmdLine containsCIS " ONIDLE ")) AND (NOT (TgtProcCmdLine containsCIS "NT AUT" OR TgtProcCmdLine containsCIS " SYSTEM" OR TgtProcCmdLine containsCIS "HIGHEST"))))

```