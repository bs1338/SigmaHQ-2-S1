# file_event_win_uac_bypass_msconfig_gui

## Title
UAC Bypass Using MSConfig Token Modification - File

## ID
41bb431f-56d8-4691-bb56-ed34e390906f

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
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\AppData\Local\Temp\pkgmgr.exe" AND TgtFilePath startswithCIS "C:\Users\"))

```