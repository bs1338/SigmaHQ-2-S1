# proc_creation_win_sc_stop_service

## Title
Stop Windows Service Via Sc.EXE

## ID
81bcb81b-5b1f-474b-b373-52c871aaa7b1

## Author
Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-05

## Tags
attack.impact, attack.t1489

## Description
Detects the stopping of a Windows service via the "sc.exe" utility

## References
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742107(v=ws.11)

## False Positives
There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behavior in particular. Filter legitimate activity accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " stop " AND TgtProcImagePath endswithCIS "\sc.exe"))

```