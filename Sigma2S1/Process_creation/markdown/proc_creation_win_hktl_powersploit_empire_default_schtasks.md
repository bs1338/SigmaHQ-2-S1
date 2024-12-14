# proc_creation_win_hktl_powersploit_empire_default_schtasks

## Title
HackTool - Default PowerSploit/Empire Scheduled Task Creation

## ID
56c217c3-2de2-479b-990f-5c109ba8458f

## Author
Markus Neis, @Karneades

## Date
2018-03-06

## Tags
attack.execution, attack.persistence, attack.privilege-escalation, attack.s0111, attack.g0022, attack.g0060, car.2013-08-001, attack.t1053.005, attack.t1059.001

## Description
Detects the creation of a schtask via PowerSploit or Empire Default Configuration.

## References
https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/powershell/persistence/userland/schtasks.py

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/SC ONLOGON" OR TgtProcCmdLine containsCIS "/SC DAILY /ST" OR TgtProcCmdLine containsCIS "/SC ONIDLE" OR TgtProcCmdLine containsCIS "/SC HOURLY") AND (TgtProcCmdLine containsCIS "/Create" AND TgtProcCmdLine containsCIS "powershell.exe -NonI" AND TgtProcCmdLine containsCIS "/TN Updater /TR") AND TgtProcImagePath endswithCIS "\schtasks.exe" AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")))

```