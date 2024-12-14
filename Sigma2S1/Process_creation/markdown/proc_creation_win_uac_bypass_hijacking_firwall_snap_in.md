# proc_creation_win_uac_bypass_hijacking_firwall_snap_in

## Title
UAC Bypass via Windows Firewall Snap-In Hijack

## ID
e52cb31c-10ed-4aea-bcb7-593c9f4a315b

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-27

## Tags
attack.privilege-escalation, attack.t1548

## Description
Detects attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in

## References
https://www.elastic.co/guide/en/security/current/uac-bypass-via-windows-firewall-snap-in-hijack.html#uac-bypass-via-windows-firewall-snap-in-hijack

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "WF.msc" AND SrcProcImagePath endswithCIS "\mmc.exe") AND (NOT TgtProcImagePath endswithCIS "\WerFault.exe")))

```