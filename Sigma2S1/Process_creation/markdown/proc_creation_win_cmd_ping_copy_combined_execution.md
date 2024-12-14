# proc_creation_win_cmd_ping_copy_combined_execution

## Title
Potentially Suspicious Ping/Copy Command Combination

## ID
ded2b07a-d12f-4284-9b76-653e37b6c8b0

## Author
X__Junior (Nextron Systems)

## Date
2023-07-18

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects uncommon and potentially suspicious one-liner command containing both "ping" and "copy" at the same time, which is usually used by malware.


## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ping" AND TgtProcCmdLine containsCIS "copy ") AND (TgtProcCmdLine containsCIS " -n " OR TgtProcCmdLine containsCIS " /n " OR TgtProcCmdLine containsCIS " â€“n " OR TgtProcCmdLine containsCIS " â€”n " OR TgtProcCmdLine containsCIS " â€•n ") AND (TgtProcCmdLine containsCIS " -y " OR TgtProcCmdLine containsCIS " /y " OR TgtProcCmdLine containsCIS " â€“y " OR TgtProcCmdLine containsCIS " â€”y " OR TgtProcCmdLine containsCIS " â€•y ") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```