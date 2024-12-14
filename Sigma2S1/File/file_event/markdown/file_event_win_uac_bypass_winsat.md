# file_event_win_uac_bypass_winsat

## Title
UAC Bypass Abusing Winsat Path Parsing - File

## ID
155dbf56-e0a4-4dd0-8905-8a98705045e8

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
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\AppData\Local\Temp\system32\winsat.exe" OR TgtFilePath endswithCIS "\AppData\Local\Temp\system32\winmm.dll") AND TgtFilePath startswithCIS "C:\Users\"))

```