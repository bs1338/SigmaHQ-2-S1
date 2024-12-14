# proc_creation_win_schtasks_creation

## Title
Scheduled Task Creation Via Schtasks.EXE

## ID
92626ddd-662c-49e3-ac59-f6535f12d189

## Author
Florian Roth (Nextron Systems)

## Date
2019-01-16

## Tags
attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005, attack.s0111, car.2013-08-001, stp.1u

## Description
Detects the creation of scheduled tasks by user accounts via the "schtasks" utility.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create

## False Positives
Administrative activity
Software installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /create " AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (NOT (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI"))))

```