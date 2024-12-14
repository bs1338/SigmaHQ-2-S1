# proc_creation_win_ksetup_password_change_computer

## Title
Computer Password Change Via Ksetup.EXE

## ID
de16d92c-c446-4d53-8938-10aeef41c8b6

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-06

## Tags
attack.execution

## Description
Detects password change for the computer's domain account or host principal via "ksetup.exe"

## References
https://twitter.com/Oddvarmoe/status/1641712700605513729
https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /setcomputerpassword " AND TgtProcImagePath endswithCIS "\ksetup.exe"))

```