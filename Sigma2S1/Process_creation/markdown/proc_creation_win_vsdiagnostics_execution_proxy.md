# proc_creation_win_vsdiagnostics_execution_proxy

## Title
Potential Binary Proxy Execution Via VSDiagnostics.EXE

## ID
ac1c92b4-ac81-405a-9978-4604d78cc47e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-03

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.

## References
https://twitter.com/0xBoku/status/1679200664013135872

## False Positives
Legitimate usage for tracing and diagnostics purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /launch:" OR TgtProcCmdLine containsCIS " -launch:") AND TgtProcCmdLine containsCIS "start" AND TgtProcImagePath endswithCIS "\VSDiagnostics.exe"))

```