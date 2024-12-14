# file_event_win_powershell_drop_powershell

## Title
PowerShell Script Dropped Via PowerShell.EXE

## ID
576426ad-0131-4001-ae01-be175da0c108

## Author
frack113

## Date
2023-05-09

## Tags
attack.persistence

## Description
Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence.

## References
https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

## False Positives
False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND TgtFilePath endswithCIS ".ps1") AND (NOT ((TgtFilePath containsCIS "\AppData\Local\Temp\" AND TgtFilePath startswithCIS "C:\Users\") OR TgtFilePath containsCIS "__PSScriptPolicyTest_" OR TgtFilePath startswithCIS "C:\Windows\Temp\"))))

```