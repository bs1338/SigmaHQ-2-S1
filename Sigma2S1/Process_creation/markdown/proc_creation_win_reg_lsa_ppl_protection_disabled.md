# proc_creation_win_reg_lsa_ppl_protection_disabled

## Title
LSA PPL Protection Disabled Via Reg.EXE

## ID
8c0eca51-0f88-4db2-9183-fdfb10c703f9

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-22

## Tags
attack.defense-evasion, attack.t1562.010

## Description
Detects the usage of the "reg.exe" utility to disable PPL protection on the LSA process

## References
https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "SYSTEM\CurrentControlSet\Control\Lsa" AND (TgtProcCmdLine containsCIS " add " AND TgtProcCmdLine containsCIS " /d 0" AND TgtProcCmdLine containsCIS " /v RunAsPPL ")) AND TgtProcImagePath endswithCIS "\reg.exe"))

```