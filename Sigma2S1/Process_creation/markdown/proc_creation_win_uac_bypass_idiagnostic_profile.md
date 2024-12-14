# proc_creation_win_uac_bypass_idiagnostic_profile

## Title
UAC Bypass Using IDiagnostic Profile

## ID
4cbef972-f347-4170-b62a-8253f6168e6d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-03

## Tags
attack.execution, attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the "IDiagnosticProfileUAC" UAC bypass technique

## References
https://github.com/Wh04m1001/IDiagnosticProfileUAC

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcCmdLine containsCIS " /Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}" AND SrcProcImagePath endswithCIS "\DllHost.exe"))

```