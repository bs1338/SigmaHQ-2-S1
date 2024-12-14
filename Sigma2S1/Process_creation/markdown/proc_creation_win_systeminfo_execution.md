# proc_creation_win_systeminfo_execution

## Title
Suspicious Execution of Systeminfo

## ID
0ef56343-059e-4cb6-adc1-4c3c967c5e46

## Author
frack113

## Date
2022-01-01

## Tags
attack.discovery, attack.t1082

## Description
Detects usage of the "systeminfo" command to retrieve information

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-1---system-information-discovery
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "\systeminfo.exe")

```