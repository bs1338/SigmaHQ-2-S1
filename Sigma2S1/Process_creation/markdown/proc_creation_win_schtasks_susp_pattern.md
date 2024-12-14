# proc_creation_win_schtasks_susp_pattern

## Title
Suspicious Command Patterns In Scheduled Task Creation

## ID
f2c64357-b1d2-41b7-849f-34d2682c0fad

## Author
Florian Roth (Nextron Systems)

## Date
2022-02-23

## Tags
attack.execution, attack.t1053.005

## Description
Detects scheduled task creation using "schtasks" that contain potentially suspicious or uncommon commands

## References
https://app.any.run/tasks/512c1352-6380-4436-b27d-bb62f0c020d6/
https://twitter.com/RedDrip7/status/1506480588827467785
https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/devil-bait/NCSC-MAR-Devil-Bait.pdf

## False Positives
Software installers that run from temporary folders and also install scheduled tasks are expected to generate some false positives

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/Create " AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (((TgtProcCmdLine containsCIS "/sc minute " OR TgtProcCmdLine containsCIS "/ru system ") AND (TgtProcCmdLine containsCIS "cmd /c" OR TgtProcCmdLine containsCIS "cmd /k" OR TgtProcCmdLine containsCIS "cmd /r" OR TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd.exe /r ")) OR (TgtProcCmdLine containsCIS " -decode " OR TgtProcCmdLine containsCIS " -enc " OR TgtProcCmdLine containsCIS " -w hidden " OR TgtProcCmdLine containsCIS " bypass " OR TgtProcCmdLine containsCIS " IEX" OR TgtProcCmdLine containsCIS ".DownloadData" OR TgtProcCmdLine containsCIS ".DownloadFile" OR TgtProcCmdLine containsCIS ".DownloadString" OR TgtProcCmdLine containsCIS "/c start /min " OR TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "mshta http" OR TgtProcCmdLine containsCIS "mshta.exe http") OR ((TgtProcCmdLine containsCIS ":\ProgramData\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Tmp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\" OR TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%Temp%" OR TgtProcCmdLine containsCIS "%tmp%") AND (TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "curl" OR TgtProcCmdLine containsCIS "wscript")))))

```