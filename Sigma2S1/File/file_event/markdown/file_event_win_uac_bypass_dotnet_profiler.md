# file_event_win_uac_bypass_dotnet_profiler

## Title
UAC Bypass Using .NET Code Profiler on MMC

## ID
93a19907-d4f9-4deb-9f91-aac4692776a6

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using .NET Code Profiler and mmc.exe DLL hijacking (UACMe 39)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\AppData\Local\Temp\pe386.dll" AND TgtFilePath startswithCIS "C:\Users\"))

```