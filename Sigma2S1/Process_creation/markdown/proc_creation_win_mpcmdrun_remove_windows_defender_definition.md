# proc_creation_win_mpcmdrun_remove_windows_defender_definition

## Title
Windows Defender Definition Files Removed

## ID
9719a8aa-401c-41af-8108-ced7ec9cd75c

## Author
frack113

## Date
2021-07-07

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -RemoveDefinitions" AND TgtProcCmdLine containsCIS " -All") AND TgtProcImagePath endswithCIS "\MpCmdRun.exe"))

```