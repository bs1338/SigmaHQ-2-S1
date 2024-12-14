# proc_creation_win_uac_bypass_wmp

## Title
UAC Bypass Using Windows Media Player - Process

## ID
0058b9e5-bcd7-40d4-9205-95ca5a16d7b2

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath = "C:\Program Files\Windows Media Player\osk.exe" OR (TgtProcImagePath = "C:\Windows\System32\cmd.exe" AND SrcProcCmdLine = "\"C:\Windows\system32\mmc.exe\" \"C:\Windows\system32\eventvwr.msc\" /s")) AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288"))))

```