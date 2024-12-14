# proc_creation_win_secedit_execution

## Title
Potential Suspicious Activity Using SeCEdit

## ID
c2c76b77-32be-4d1f-82c9-7e544bdfe0eb

## Author
Janantha Marasinghe

## Date
2022-11-18

## Tags
attack.discovery, attack.persistence, attack.defense-evasion, attack.credential-access, attack.privilege-escalation, attack.t1562.002, attack.t1547.001, attack.t1505.005, attack.t1556.002, attack.t1562, attack.t1574.007, attack.t1564.002, attack.t1546.008, attack.t1546.007, attack.t1547.014, attack.t1547.010, attack.t1547.002, attack.t1557, attack.t1082

## Description
Detects potential suspicious behaviour using secedit.exe. Such as exporting or modifying the security policy

## References
https://blueteamops.medium.com/secedit-and-i-know-it-595056dee53d
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit

## False Positives
Legitimate administrative use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\secedit.exe" AND ((TgtProcCmdLine containsCIS "/configure" AND TgtProcCmdLine containsCIS "/db") OR (TgtProcCmdLine containsCIS "/export" AND TgtProcCmdLine containsCIS "/cfg"))))

```