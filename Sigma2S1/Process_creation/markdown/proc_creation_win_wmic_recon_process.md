# proc_creation_win_wmic_recon_process

## Title
Process Reconnaissance Via Wmic.EXE

## ID
221b251a-357a-49a9-920a-271802777cc0

## Author
frack113

## Date
2022-01-01

## Tags
attack.execution, attack.t1047

## Description
Detects the execution of "wmic" with the "process" flag, which adversary might use to list processes running on the compromised host or list installed software hotfixes and patches.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "process" AND TgtProcImagePath endswithCIS "\WMIC.exe") AND (NOT (TgtProcCmdLine containsCIS "call" AND TgtProcCmdLine containsCIS "create"))))

```