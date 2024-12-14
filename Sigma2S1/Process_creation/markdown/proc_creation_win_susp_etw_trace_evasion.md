# proc_creation_win_susp_etw_trace_evasion

## Title
ETW Trace Evasion Activity

## ID
a238b5d0-ce2d-4414-a676-7a531b3d13d6

## Author
@neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2019-03-22

## Tags
attack.defense-evasion, attack.t1070, attack.t1562.006, car.2016-04-002

## Description
Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.


## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
https://abuse.io/lockergoga.txt
https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "cl" AND TgtProcCmdLine containsCIS "/Trace") OR (TgtProcCmdLine containsCIS "clear-log" AND TgtProcCmdLine containsCIS "/Trace") OR (TgtProcCmdLine containsCIS "sl" AND TgtProcCmdLine containsCIS "/e:false") OR (TgtProcCmdLine containsCIS "set-log" AND TgtProcCmdLine containsCIS "/e:false") OR (TgtProcCmdLine containsCIS "logman" AND TgtProcCmdLine containsCIS "update" AND TgtProcCmdLine containsCIS "trace" AND TgtProcCmdLine containsCIS "--p" AND TgtProcCmdLine containsCIS "-ets") OR TgtProcCmdLine containsCIS "Remove-EtwTraceProvider" OR (TgtProcCmdLine containsCIS "Set-EtwTraceProvider" AND TgtProcCmdLine containsCIS "0x11")))

```