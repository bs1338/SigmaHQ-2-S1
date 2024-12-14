# proc_creation_win_whoami_all_execution

## Title
Enumerate All Information With Whoami.EXE

## ID
c248c896-e412-4279-8c15-1c558067b6fa

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-12-04

## Tags
attack.discovery, attack.t1033, car.2016-03-001

## Description
Detects the execution of "whoami.exe" with the "/all" flag

## References
https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
https://www.youtube.com/watch?v=DsJ9ByX84o4&t=6s

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -all" OR TgtProcCmdLine containsCIS " /all" OR TgtProcCmdLine containsCIS " â€“all" OR TgtProcCmdLine containsCIS " â€”all" OR TgtProcCmdLine containsCIS " â€•all") AND TgtProcImagePath endswithCIS "\whoami.exe"))

```