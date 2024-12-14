# proc_creation_win_dotnet_trace_lolbin_execution

## Title
Binary Proxy Execution Via Dotnet-Trace.EXE

## ID
9257c05b-4a4a-48e5-a670-b7b073cf401b

## Author
Jimmy Bayne (@bohops)

## Date
2024-01-02

## Tags
attack.execution, attack.defense-evasion, attack.t1218

## Description
Detects commandline arguments for executing a child process via dotnet-trace.exe

## References
https://twitter.com/bohops/status/1740022869198037480

## False Positives
Legitimate usage of the utility in order to debug and trace a program.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-- " AND TgtProcCmdLine containsCIS "collect") AND TgtProcImagePath endswithCIS "\dotnet-trace.exe"))

```