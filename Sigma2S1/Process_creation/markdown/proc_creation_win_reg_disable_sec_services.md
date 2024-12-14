# proc_creation_win_reg_disable_sec_services

## Title
Security Service Disabled Via Reg.EXE

## ID
5e95028c-5229-4214-afae-d653d573d0ec

## Author
Florian Roth (Nextron Systems), John Lambert (idea), elhoim

## Date
2021-07-14

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects execution of "reg.exe" to disable security services such as Windows Defender.

## References
https://twitter.com/JohnLaTwC/status/1415295021041979392
https://github.com/gordonbay/Windows-On-Reins/blob/e587ac7a0407847865926d575e3c46f68cf7c68d/wor.ps1
https://vms.drweb.fr/virus/?i=24144899
https://bidouillesecurity.com/disable-windows-defender-in-powershell/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "\AppIDSvc" OR TgtProcCmdLine containsCIS "\MsMpSvc" OR TgtProcCmdLine containsCIS "\NisSrv" OR TgtProcCmdLine containsCIS "\SecurityHealthService" OR TgtProcCmdLine containsCIS "\Sense" OR TgtProcCmdLine containsCIS "\UsoSvc" OR TgtProcCmdLine containsCIS "\WdBoot" OR TgtProcCmdLine containsCIS "\WdFilter" OR TgtProcCmdLine containsCIS "\WdNisDrv" OR TgtProcCmdLine containsCIS "\WdNisSvc" OR TgtProcCmdLine containsCIS "\WinDefend" OR TgtProcCmdLine containsCIS "\wscsvc" OR TgtProcCmdLine containsCIS "\wuauserv") AND (TgtProcCmdLine containsCIS "d 4" AND TgtProcCmdLine containsCIS "v Start")) AND (TgtProcCmdLine containsCIS "reg" AND TgtProcCmdLine containsCIS "add")))

```