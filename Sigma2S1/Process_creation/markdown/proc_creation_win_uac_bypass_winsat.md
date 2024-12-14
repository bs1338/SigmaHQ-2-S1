# proc_creation_win_uac_bypass_winsat

## Title
UAC Bypass Abusing Winsat Path Parsing - Process

## ID
7a01183d-71a2-46ad-ad5c-acd989ac1793

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288")) AND SrcProcCmdLine containsCIS "C:\Windows \system32\winsat.exe" AND SrcProcImagePath endswithCIS "\AppData\Local\Temp\system32\winsat.exe"))

```