# proc_creation_win_takeown_recursive_own

## Title
Suspicious Recursive Takeown

## ID
554601fb-9b71-4bcc-abf4-21a611be4fde

## Author
frack113

## Date
2022-01-30

## Tags
attack.defense-evasion, attack.t1222.001

## Description
Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility

## False Positives
Scripts created by developers and admins
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/f " AND TgtProcCmdLine containsCIS "/r") AND TgtProcImagePath endswithCIS "\takeown.exe"))

```