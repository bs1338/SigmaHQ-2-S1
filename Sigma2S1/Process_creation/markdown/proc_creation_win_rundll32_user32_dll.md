# proc_creation_win_rundll32_user32_dll

## Title
Suspicious Workstation Locking via Rundll32

## ID
3b5b0213-0460-4e3f-8937-3abf98ff7dcc

## Author
frack113

## Date
2022-06-04

## Tags
attack.defense-evasion

## Description
Detects a suspicious call to the user32.dll function that locks the user workstation

## References
https://app.any.run/tasks/2aef9c63-f944-4763-b3ef-81eee209d128/

## False Positives
Scripts or links on the user desktop used to lock the workstation instead of Windows+L or the menu option

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "user32.dll," AND TgtProcImagePath endswithCIS "\rundll32.exe" AND SrcProcImagePath endswithCIS "\cmd.exe" AND TgtProcCmdLine containsCIS "LockWorkStation"))

```