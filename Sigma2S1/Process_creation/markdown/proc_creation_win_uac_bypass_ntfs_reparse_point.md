# proc_creation_win_uac_bypass_ntfs_reparse_point

## Title
UAC Bypass Using NTFS Reparse Point - Process

## ID
39ed3c80-e6a1-431b-9df3-911ac53d08a7

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
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS "\AppData\Local\Temp\update.msu" AND TgtProcCmdLine startswithCIS "\"C:\Windows\system32\wusa.exe\"  /quiet C:\Users\" AND (TgtProcIntegrityLevel In ("High","System","S-1-16-16384","S-1-16-12288"))) OR ((TgtProcCmdLine containsCIS "C:\Users\" AND TgtProcCmdLine containsCIS "\AppData\Local\Temp\" AND TgtProcCmdLine containsCIS "\dismhost.exe {") AND TgtProcImagePath endswithCIS "\DismHost.exe" AND (TgtProcIntegrityLevel In ("High","System")) AND SrcProcCmdLine = "\"C:\Windows\system32\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\Windows\system32\pe386\" /ignorecheck")))

```