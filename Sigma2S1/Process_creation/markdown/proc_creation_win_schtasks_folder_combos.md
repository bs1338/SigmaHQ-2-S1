# proc_creation_win_schtasks_folder_combos

## Title
Schtasks From Suspicious Folders

## ID
8a8379b8-780b-4dbf-b1e9-31c8d112fefb

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-15

## Tags
attack.execution, attack.t1053.005

## Description
Detects scheduled task creations that have suspicious action command and folder combinations

## References
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/lazarus-dream-job-chemical

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "C:\ProgramData\" OR TgtProcCmdLine containsCIS "%ProgramData%") AND (TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "pwsh" OR TgtProcCmdLine containsCIS "cmd /c " OR TgtProcCmdLine containsCIS "cmd /k " OR TgtProcCmdLine containsCIS "cmd /r " OR TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd.exe /r ") AND TgtProcCmdLine containsCIS " /create " AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```