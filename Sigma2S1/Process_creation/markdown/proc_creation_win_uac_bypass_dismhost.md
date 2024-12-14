# proc_creation_win_uac_bypass_dismhost

## Title
UAC Bypass Using DismHost

## ID
853e74f9-9392-4935-ad3b-2e8c040dae86

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND (SrcProcImagePath containsCIS "C:\Users\" AND SrcProcImagePath containsCIS "\AppData\Local\Temp\" AND SrcProcImagePath containsCIS "\DismHost.exe")))

```