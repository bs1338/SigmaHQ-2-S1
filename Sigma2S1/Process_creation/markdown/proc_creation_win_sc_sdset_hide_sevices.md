# proc_creation_win_sc_sdset_hide_sevices

## Title
Service DACL Abuse To Hide Services Via Sc.EXE

## ID
a537cfc3-4297-4789-92b5-345bfd845ad0

## Author
Andreas Hunkeler (@Karneades)

## Date
2021-12-20

## Tags
attack.persistence, attack.defense-evasion, attack.privilege-escalation, attack.t1574.011

## Description
Detects usage of the "sc.exe" utility adding a new service with special permission seen used by threat actors which makes the service hidden and unremovable.

## References
https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
https://twitter.com/Alh4zr3d/status/1580925761996828672
https://itconnect.uw.edu/tools-services-support/it-systems-infrastructure/msinf/other-help/understanding-sddl-syntax/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "sdset" AND TgtProcCmdLine containsCIS "DCLCWPDTSD") AND TgtProcImagePath endswithCIS "\sc.exe"))

```