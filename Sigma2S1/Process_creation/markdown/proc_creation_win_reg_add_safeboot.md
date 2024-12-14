# proc_creation_win_reg_add_safeboot

## Title
Add SafeBoot Keys Via Reg Utility

## ID
d7662ff6-9e97-4596-a61d-9839e32dee8d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-02

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects execution of "reg.exe" commands with the "add" or "copy" flags on safe boot registry keys. Often used by attacker to allow the ransomware to work in safe mode as some security products do not

## References
https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " copy " OR TgtProcCmdLine containsCIS " add ") AND TgtProcImagePath endswithCIS "\reg.exe" AND TgtProcCmdLine containsCIS "\SYSTEM\CurrentControlSet\Control\SafeBoot"))

```