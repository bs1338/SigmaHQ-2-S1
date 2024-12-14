# proc_creation_win_mssql_susp_child_process

## Title
Suspicious Child Process Of SQL Server

## ID
869b9ca7-9ea2-4a5a-8325-e80e62f75445

## Author
FPT.EagleEye Team, wagga

## Date
2020-12-11

## Tags
attack.t1505.003, attack.t1190, attack.initial-access, attack.persistence, attack.privilege-escalation

## Description
Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.

## References
Internal Research

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\bash.exe" OR TgtProcImagePath endswithCIS "\bitsadmin.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\netstat.exe" OR TgtProcImagePath endswithCIS "\nltest.exe" OR TgtProcImagePath endswithCIS "\ping.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\sh.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\tasklist.exe" OR TgtProcImagePath endswithCIS "\wsl.exe") AND SrcProcImagePath endswithCIS "\sqlservr.exe") AND (NOT (TgtProcCmdLine startswithCIS "\"C:\Windows\system32\cmd.exe\" " AND TgtProcImagePath = "C:\Windows\System32\cmd.exe" AND SrcProcImagePath endswithCIS "DATEV_DBENGINE\MSSQL\Binn\sqlservr.exe" AND SrcProcImagePath startswithCIS "C:\Program Files\Microsoft SQL Server\"))))

```