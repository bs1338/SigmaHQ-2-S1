# file_event_win_sysinternals_livekd_driver_susp_creation

## Title
LiveKD Driver Creation By Uncommon Process

## ID
059c5af9-5131-4d8d-92b2-de4ad6146712

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-16

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects the creation of the LiveKD driver by a process image other than "livekd.exe".

## References
Internal Research

## False Positives
Administrators might rename LiveKD before its usage which could trigger this. Add additional names you use to the filter

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath = "C:\Windows\System32\drivers\LiveKdD.SYS" AND (NOT (SrcProcImagePath endswithCIS "\livekd.exe" OR SrcProcImagePath endswithCIS "\livek64.exe"))))

```