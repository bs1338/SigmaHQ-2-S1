# proc_creation_win_uac_bypass_computerdefaults

## Title
UAC Bypass Tools Using ComputerDefaults

## ID
3c05e90d-7eba-4324-9972-5d7f711a60a8

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-31

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath = "C:\Windows\System32\ComputerDefaults.exe" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288"))) AND (NOT (SrcProcImagePath containsCIS ":\Windows\System32" OR SrcProcImagePath containsCIS ":\Program Files"))))

```