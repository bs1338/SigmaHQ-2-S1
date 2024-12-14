# proc_creation_win_net_use_password_plaintext

## Title
Password Provided In Command Line Of Net.EXE

## ID
d4498716-1d52-438f-8084-4a603157d131

## Author
Tim Shelton (HAWK.IO)

## Date
2021-12-09

## Tags
attack.defense-evasion, attack.initial-access, attack.persistence, attack.privilege-escalation, attack.lateral-movement, attack.t1021.002, attack.t1078

## Description
Detects a when net.exe is called with a password in the command line

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " use " AND TgtProcCmdLine = "*:*\*" AND TgtProcCmdLine = "*/USER:* *") AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")) AND (NOT TgtProcCmdLine endswithCIS " ")))

```