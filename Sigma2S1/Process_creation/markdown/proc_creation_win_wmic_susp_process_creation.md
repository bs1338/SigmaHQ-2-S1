# proc_creation_win_wmic_susp_process_creation

## Title
Suspicious Process Created Via Wmic.EXE

## ID
3c89a1e8-0fba-449e-8f1b-8409d6267ec8

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2020-10-12

## Tags
attack.execution, attack.t1047

## Description
Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.

## References
https://thedfirreport.com/2020/10/08/ryuks-return/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "bitsadmin" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "cmd.exe /c " OR TgtProcCmdLine containsCIS "cmd.exe /k " OR TgtProcCmdLine containsCIS "cmd.exe /r " OR TgtProcCmdLine containsCIS "cmd /c " OR TgtProcCmdLine containsCIS "cmd /k " OR TgtProcCmdLine containsCIS "cmd /r " OR TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "pwsh" OR TgtProcCmdLine containsCIS "certutil" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "%temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "%ProgramData%" OR TgtProcCmdLine containsCIS "%appdata%" OR TgtProcCmdLine containsCIS "%comspec%" OR TgtProcCmdLine containsCIS "%localappdata%") AND (TgtProcCmdLine containsCIS "process " AND TgtProcCmdLine containsCIS "call " AND TgtProcCmdLine containsCIS "create ")))

```