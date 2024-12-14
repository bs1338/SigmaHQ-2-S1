# proc_creation_win_logman_disable_eventlog

## Title
Suspicious Windows Trace ETW Session Tamper Via Logman.EXE

## ID
cd1f961e-0b96-436b-b7c6-38da4583ec00

## Author
Florian Roth (Nextron Systems)

## Date
2021-02-11

## Tags
attack.defense-evasion, attack.t1562.001, attack.t1070.001

## Description
Detects the execution of "logman" utility in order to disable or delete Windows trace sessions

## References
https://twitter.com/0gtweet/status/1359039665232306183?s=21
https://ss64.com/nt/logman.html

## False Positives
Legitimate deactivation by administrative staff
Installer tools that disable services, e.g. before log collection agent installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "stop " OR TgtProcCmdLine containsCIS "delete ") AND TgtProcImagePath endswithCIS "\logman.exe" AND (TgtProcCmdLine containsCIS "Circular Kernel Context Logger" OR TgtProcCmdLine containsCIS "EventLog-" OR TgtProcCmdLine containsCIS "SYSMON TRACE" OR TgtProcCmdLine containsCIS "SysmonDnsEtwSession")))

```