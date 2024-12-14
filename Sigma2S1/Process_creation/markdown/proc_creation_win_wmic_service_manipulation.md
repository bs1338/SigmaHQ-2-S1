# proc_creation_win_wmic_service_manipulation

## Title
Service Started/Stopped Via Wmic.EXE

## ID
0b7163dc-7eee-4960-af17-c0cd517f92da

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-20

## Tags
attack.execution, attack.t1047

## Description
Detects usage of wmic to start or stop a service

## References
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "stopservice" OR TgtProcCmdLine containsCIS "startservice") AND (TgtProcCmdLine containsCIS " service " AND TgtProcCmdLine containsCIS " call ")) AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```