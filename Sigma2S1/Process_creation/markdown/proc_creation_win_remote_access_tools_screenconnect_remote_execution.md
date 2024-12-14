# proc_creation_win_remote_access_tools_screenconnect_remote_execution

## Title
Remote Access Tool - ScreenConnect Remote Command Execution

## ID
b1f73849-6329-4069-bc8f-78a604bb8b23

## Author
Ali Alwashali

## Date
2023-10-10

## Tags
attack.execution, attack.t1059.003

## Description
Detects the execution of a system command via the ScreenConnect RMM service.

## References
https://github.com/SigmaHQ/sigma/pull/4467

## False Positives
Legitimate use of ScreenConnect. Disable this rule if ScreenConnect is heavily used.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\TEMP\ScreenConnect\" AND TgtProcImagePath endswithCIS "\cmd.exe" AND SrcProcImagePath endswithCIS "\ScreenConnect.ClientService.exe"))

```