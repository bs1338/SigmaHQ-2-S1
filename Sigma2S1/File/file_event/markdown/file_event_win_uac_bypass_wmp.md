# file_event_win_uac_bypass_wmp

## Title
UAC Bypass Using Windows Media Player - File

## ID
68578b43-65df-4f81-9a9b-92f32711a951

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-23

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS "\AppData\Local\Temp\OskSupport.dll" AND TgtFilePath startswithCIS "C:\Users\") OR (SrcProcImagePath = "C:\Windows\system32\DllHost.exe" AND TgtFilePath = "C:\Program Files\Windows Media Player\osk.exe")))

```