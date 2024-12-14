# proc_creation_win_sc_disable_service

## Title
Service StartupType Change Via Sc.EXE

## ID
85c312b7-f44d-4a51-a024-d671c40b49fc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.execution, attack.defense-evasion, attack.t1562.001

## Description
Detect the use of "sc.exe" to change the startup type of a service to "disabled" or "demand"

## References
https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955

## False Positives
False positives may occur with troubleshooting scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "disabled" OR TgtProcCmdLine containsCIS "demand") AND (TgtProcCmdLine containsCIS " config " AND TgtProcCmdLine containsCIS "start")) AND TgtProcImagePath endswithCIS "\sc.exe"))

```