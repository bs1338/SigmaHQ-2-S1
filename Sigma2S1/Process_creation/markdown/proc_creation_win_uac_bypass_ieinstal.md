# proc_creation_win_uac_bypass_ieinstal

## Title
UAC Bypass Using IEInstal - Process

## ID
80fc36aa-945e-4181-89f2-2f907ab6775d

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath containsCIS "\AppData\Local\Temp\" AND TgtProcImagePath endswithCIS "consent.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcImagePath endswithCIS "\ieinstal.exe"))

```