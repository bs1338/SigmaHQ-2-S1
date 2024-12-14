# proc_creation_win_reg_query_registry

## Title
Potential Configuration And Service Reconnaissance Via Reg.EXE

## ID
970007b7-ce32-49d0-a4a4-fbef016950bd

## Author
Timur Zinniatullin, oscd.community

## Date
2019-10-21

## Tags
attack.discovery, attack.t1012, attack.t1007

## Description
Detects the usage of "reg.exe" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1012/T1012.md

## False Positives
Discord

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "query" AND TgtProcImagePath endswithCIS "\reg.exe" AND (TgtProcCmdLine containsCIS "currentVersion\windows" OR TgtProcCmdLine containsCIS "winlogon\" OR TgtProcCmdLine containsCIS "currentVersion\shellServiceObjectDelayLoad" OR TgtProcCmdLine containsCIS "currentVersion\run" OR TgtProcCmdLine containsCIS "currentVersion\policies\explorer\run" OR TgtProcCmdLine containsCIS "currentcontrolset\services")))

```