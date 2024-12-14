# proc_creation_win_hktl_evil_winrm

## Title
HackTool - WinRM Access Via Evil-WinRM

## ID
a197e378-d31b-41c0-9635-cfdf1c1bb423

## Author
frack113

## Date
2022-01-07

## Tags
attack.lateral-movement, attack.t1021.006

## Description
Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-3---winrm-access-with-evil-winrm
https://github.com/Hackplayers/evil-winrm

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-i " AND TgtProcCmdLine containsCIS "-u " AND TgtProcCmdLine containsCIS "-p ") AND TgtProcImagePath endswithCIS "\ruby.exe"))

```