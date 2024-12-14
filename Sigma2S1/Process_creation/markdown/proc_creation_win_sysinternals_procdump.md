# proc_creation_win_sysinternals_procdump

## Title
Procdump Execution

## ID
2e65275c-8288-4ab4-aeb7-6274f58b6b20

## Author
Florian Roth (Nextron Systems)

## Date
2021-08-16

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects usage of the SysInternals Procdump utility

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/procdump

## False Positives
Legitimate use of procdump by a developer or administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\procdump.exe" OR TgtProcImagePath endswithCIS "\procdump64.exe"))

```