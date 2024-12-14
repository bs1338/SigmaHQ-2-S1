# proc_creation_win_hktl_meterpreter_getsystem

## Title
Potential Meterpreter/CobaltStrike Activity

## ID
15619216-e993-4721-b590-4c520615a67d

## Author
Teymur Kheirkhabarov, Ecco, Florian Roth

## Date
2019-10-26

## Tags
attack.privilege-escalation, attack.t1134.001, attack.t1134.002

## Description
Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service starting

## References
https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/

## False Positives
Commandlines containing components like cmd accidentally
Jobs and services started with cmd

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\services.exe" AND (((TgtProcCmdLine containsCIS "cmd" OR TgtProcCmdLine containsCIS "%COMSPEC%") AND (TgtProcCmdLine containsCIS "/c" AND TgtProcCmdLine containsCIS "echo" AND TgtProcCmdLine containsCIS "\pipe\")) OR (TgtProcCmdLine containsCIS "rundll32" AND TgtProcCmdLine containsCIS ".dll,a" AND TgtProcCmdLine containsCIS "/p:")) AND (NOT TgtProcCmdLine containsCIS "MpCmdRun")))

```