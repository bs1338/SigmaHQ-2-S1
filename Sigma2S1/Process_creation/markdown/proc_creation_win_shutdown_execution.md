# proc_creation_win_shutdown_execution

## Title
Suspicious Execution of Shutdown

## ID
34ebb878-1b15-4895-b352-ca2eeb99b274

## Author
frack113

## Date
2022-01-01

## Tags
attack.impact, attack.t1529

## Description
Use of the commandline to shutdown or reboot windows

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/r " OR TgtProcCmdLine containsCIS "/s ") AND TgtProcImagePath endswithCIS "\shutdown.exe"))

```