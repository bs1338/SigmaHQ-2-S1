# proc_creation_win_cmd_rmdir_execution

## Title
Directory Removal Via Rmdir

## ID
41ca393d-538c-408a-ac27-cf1e038be80c

## Author
frack113

## Date
2022-01-15

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects execution of the builtin "rmdir" command in order to delete directories.
Adversaries may delete files left behind by the actions of their intrusion activity.
Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how.
Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/erase

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/s" OR TgtProcCmdLine containsCIS "/q") AND TgtProcImagePath endswithCIS "\cmd.exe" AND TgtProcCmdLine containsCIS "rmdir"))

```