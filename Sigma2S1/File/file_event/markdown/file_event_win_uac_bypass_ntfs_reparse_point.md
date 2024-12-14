# file_event_win_uac_bypass_ntfs_reparse_point

## Title
UAC Bypass Using NTFS Reparse Point - File

## ID
7fff6773-2baa-46de-a24a-b6eec1aba2d1

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\AppData\Local\Temp\api-ms-win-core-kernel32-legacy-l1.DLL" AND TgtFilePath startswithCIS "C:\Users\"))

```