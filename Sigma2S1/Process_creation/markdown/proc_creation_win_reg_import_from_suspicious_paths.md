# proc_creation_win_reg_import_from_suspicious_paths

## Title
Potential Suspicious Registry File Imported Via Reg.EXE

## ID
62e0298b-e994-4189-bc87-bc699aa62d97

## Author
frack113, Nasreddine Bencherchali

## Date
2022-08-01

## Tags
attack.t1112, attack.defense-evasion

## Description
Detects the import of '.reg' files from suspicious paths using the 'reg.exe' utility

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-import

## False Positives
Legitimate import of keys

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " import " AND TgtProcImagePath endswithCIS "\reg.exe" AND (TgtProcCmdLine containsCIS "C:\Users\" OR TgtProcCmdLine containsCIS "%temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "%appdata%" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "C:\Windows\Temp\" OR TgtProcCmdLine containsCIS "C:\ProgramData\")))

```