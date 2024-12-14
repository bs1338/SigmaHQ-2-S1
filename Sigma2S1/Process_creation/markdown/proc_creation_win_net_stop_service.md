# proc_creation_win_net_stop_service

## Title
Stop Windows Service Via Net.EXE

## ID
88872991-7445-4a22-90b2-a3adadb0e827

## Author
Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-05

## Tags
attack.impact, attack.t1489

## Description
Detects the stopping of a Windows service via the "net" utility.

## References
https://ss64.com/nt/net-service.html

## False Positives
There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " stop " AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```