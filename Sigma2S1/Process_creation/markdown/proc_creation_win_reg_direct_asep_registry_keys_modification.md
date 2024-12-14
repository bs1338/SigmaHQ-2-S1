# proc_creation_win_reg_direct_asep_registry_keys_modification

## Title
Direct Autorun Keys Modification

## ID
24357373-078f-44ed-9ac4-6d334a668a11

## Author
Victor Sergeev, Daniil Yugoslavskiy, oscd.community

## Date
2019-10-25

## Tags
attack.persistence, attack.t1547.001

## Description
Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md

## False Positives
Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reasons.
Legitimate administrator sets up autorun keys for legitimate reasons.
Discord

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "add" AND TgtProcImagePath endswithCIS "\reg.exe") AND (TgtProcCmdLine containsCIS "\software\Microsoft\Windows\CurrentVersion\Run" OR TgtProcCmdLine containsCIS "\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" OR TgtProcCmdLine containsCIS "\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" OR TgtProcCmdLine containsCIS "\software\Microsoft\Windows NT\CurrentVersion\Windows" OR TgtProcCmdLine containsCIS "\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" OR TgtProcCmdLine containsCIS "\system\CurrentControlSet\Control\SafeBoot\AlternateShell")))

```