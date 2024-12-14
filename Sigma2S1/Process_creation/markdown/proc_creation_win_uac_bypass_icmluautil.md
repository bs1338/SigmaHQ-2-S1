# proc_creation_win_uac_bypass_icmluautil

## Title
UAC Bypass via ICMLuaUtil

## ID
49f2f17b-b4c8-4172-a68b-d5bf95d05130

## Author
Florian Roth (Nextron Systems), Elastic (idea)

## Date
2022-09-13

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using ICMLuaUtil Elevated COM interface

## References
https://www.elastic.co/guide/en/security/current/uac-bypass-via-icmluautil-elevated-com-interface.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((SrcProcCmdLine containsCIS "/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" OR SrcProcCmdLine containsCIS "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") AND SrcProcImagePath endswithCIS "\dllhost.exe") AND (NOT TgtProcImagePath endswithCIS "\WerFault.exe")))

```