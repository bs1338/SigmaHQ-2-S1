# proc_creation_win_net_start_service

## Title
Start Windows Service Via Net.EXE

## ID
2a072a96-a086-49fa-bcb5-15cc5a619093

## Author
Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community

## Date
2019-10-21

## Tags
attack.execution, attack.t1569.002

## Description
Detects the usage of the "net.exe" command to start a service using the "start" flag

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1569.002/T1569.002.md

## False Positives
Legitimate administrator or user executes a service for legitimate reasons.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " start " AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```