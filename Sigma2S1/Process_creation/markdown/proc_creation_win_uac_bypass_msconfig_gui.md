# proc_creation_win_uac_bypass_msconfig_gui

## Title
UAC Bypass Using MSConfig Token Modification - Process

## ID
ad92e3f9-7eb6-460e-96b1-582b0ccbb980

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine = "\"C:\Windows\system32\msconfig.exe\" -5" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcImagePath endswithCIS "\AppData\Local\Temp\pkgmgr.exe"))

```