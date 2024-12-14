# proc_creation_win_hktl_sharpup

## Title
HackTool - SharpUp PrivEsc Tool Execution

## ID
c484e533-ee16-4a93-b6ac-f0ea4868b2f1

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-20

## Tags
attack.privilege-escalation, attack.t1615, attack.t1569.002, attack.t1574.005

## Description
Detects the use of SharpUp, a tool for local privilege escalation

## References
https://github.com/GhostPack/SharpUp

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpUp.exe" OR TgtProcDisplayName = "SharpUp" OR (TgtProcCmdLine containsCIS "HijackablePaths" OR TgtProcCmdLine containsCIS "UnquotedServicePath" OR TgtProcCmdLine containsCIS "ProcessDLLHijack" OR TgtProcCmdLine containsCIS "ModifiableServiceBinaries" OR TgtProcCmdLine containsCIS "ModifiableScheduledTask" OR TgtProcCmdLine containsCIS "DomainGPPPassword" OR TgtProcCmdLine containsCIS "CachedGPPPassword")))

```