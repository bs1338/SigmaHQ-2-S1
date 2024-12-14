# file_event_win_uac_bypass_ieinstal

## Title
UAC Bypass Using IEInstal - File

## ID
bdd8157d-8e85-4397-bb82-f06cc9c71dbb

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
ObjectType = "File" AND (EndpointOS = "windows" AND (SrcProcImagePath = "C:\Program Files\Internet Explorer\IEInstal.exe" AND TgtFilePath containsCIS "\AppData\Local\Temp\" AND TgtFilePath endswithCIS "consent.exe" AND TgtFilePath startswithCIS "C:\Users\"))

```