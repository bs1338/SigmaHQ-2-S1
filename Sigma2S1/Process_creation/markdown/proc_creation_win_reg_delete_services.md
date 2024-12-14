# proc_creation_win_reg_delete_services

## Title
Service Registry Key Deleted Via Reg.EXE

## ID
05b2aa93-1210-42c8-8d9a-2fcc13b284f5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects execution of "reg.exe" commands with the "delete" flag on services registry key. Often used by attacker to remove AV software services

## References
https://www.virustotal.com/gui/file/2bcd5702a7565952c44075ac6fb946c7780526640d1264f692c7664c02c68465

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " delete " AND TgtProcImagePath endswithCIS "reg.exe" AND TgtProcCmdLine containsCIS "\SYSTEM\CurrentControlSet\services\"))

```