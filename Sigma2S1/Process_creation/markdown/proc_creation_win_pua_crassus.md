# proc_creation_win_pua_crassus

## Title
PUA - Crassus Execution

## ID
2c32b543-1058-4808-91c6-5b31b8bed6c5

## Author
pH-T (Nextron Systems)

## Date
2023-04-17

## Tags
attack.discovery, attack.t1590.001

## Description
Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.

## References
https://github.com/vu-ls/Crassus

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\Crassus.exe" OR TgtProcDisplayName containsCIS "Crassus"))

```