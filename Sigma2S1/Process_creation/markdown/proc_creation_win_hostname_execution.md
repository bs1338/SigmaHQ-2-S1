# proc_creation_win_hostname_execution

## Title
Suspicious Execution of Hostname

## ID
7be5fb68-f9ef-476d-8b51-0256ebece19e

## Author
frack113

## Date
2022-01-01

## Tags
attack.discovery, attack.t1082

## Description
Use of hostname to get information

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/hostname

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\HOSTNAME.EXE")

```