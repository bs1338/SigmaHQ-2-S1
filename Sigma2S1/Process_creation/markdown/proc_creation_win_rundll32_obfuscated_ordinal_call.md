# proc_creation_win_rundll32_obfuscated_ordinal_call

## Title
Potential Obfuscated Ordinal Call Via Rundll32

## ID
43fa5350-db63-4b8f-9a01-789a427074e1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-17

## Tags
attack.defense-evasion

## Description
Detects execution of "rundll32" with potential obfuscated ordinal calls

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "#+" OR TgtProcCmdLine containsCIS "#-") AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcCmdLine containsCIS "rundll32")))

```