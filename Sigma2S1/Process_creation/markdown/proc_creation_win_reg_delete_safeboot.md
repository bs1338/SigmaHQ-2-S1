# proc_creation_win_reg_delete_safeboot

## Title
SafeBoot Registry Key Deleted Via Reg.EXE

## ID
fc0e89b5-adb0-43c1-b749-c12a10ec37de

## Author
Nasreddine Bencherchali (Nextron Systems), Tim Shelton

## Date
2022-08-08

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects execution of "reg.exe" commands with the "delete" flag on safe boot registry keys. Often used by attacker to prevent safeboot execution of security products

## References
https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " delete " AND TgtProcCmdLine containsCIS "\SYSTEM\CurrentControlSet\Control\SafeBoot") AND TgtProcImagePath endswithCIS "reg.exe"))

```