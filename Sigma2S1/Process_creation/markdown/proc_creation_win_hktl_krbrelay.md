# proc_creation_win_hktl_krbrelay

## Title
HackTool - KrbRelay Execution

## ID
e96253b8-6b3b-4f90-9e59-3b24b99cf9b4

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-27

## Tags
attack.credential-access, attack.t1558.003

## Description
Detects the use of KrbRelay, a Kerberos relaying tool

## References
https://github.com/cube0x0/KrbRelay

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -spn " AND TgtProcCmdLine containsCIS " -clsid " AND TgtProcCmdLine containsCIS " -rbcd ") OR (TgtProcCmdLine containsCIS "shadowcred" AND TgtProcCmdLine containsCIS "clsid" AND TgtProcCmdLine containsCIS "spn") OR (TgtProcCmdLine containsCIS "spn " AND TgtProcCmdLine containsCIS "session " AND TgtProcCmdLine containsCIS "clsid ") OR TgtProcImagePath endswithCIS "\KrbRelay.exe"))

```