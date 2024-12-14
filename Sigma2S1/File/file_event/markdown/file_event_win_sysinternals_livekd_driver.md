# file_event_win_sysinternals_livekd_driver

## Title
LiveKD Driver Creation

## ID
16fe46bb-4f64-46aa-817d-ff7bec4a2352

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-16

## Tags
attack.defense-evasion, attack.privilege-escalation

## Description
Detects the creation of the LiveKD driver, which is used for live kernel debugging

## References
Internal Research

## False Positives
Legitimate usage of LiveKD for debugging purposes will also trigger this

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\livekd.exe" OR SrcProcImagePath endswithCIS "\livek64.exe") AND TgtFilePath = "C:\Windows\System32\drivers\LiveKdD.SYS"))

```