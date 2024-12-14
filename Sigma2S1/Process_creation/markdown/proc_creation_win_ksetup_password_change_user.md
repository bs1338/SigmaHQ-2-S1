# proc_creation_win_ksetup_password_change_user

## Title
Logged-On User Password Change Via Ksetup.EXE

## ID
c9783e20-4793-4164-ba96-d9ee483992c4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-06

## Tags
attack.execution

## Description
Detects password change for the logged-on user's via "ksetup.exe"

## References
https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ksetup

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /ChangePassword " AND TgtProcImagePath endswithCIS "\ksetup.exe"))

```