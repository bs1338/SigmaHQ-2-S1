# file_event_win_powershell_drop_binary_or_script

## Title
Potential Binary Or Script Dropper Via PowerShell

## ID
7047d730-036f-4f40-b9d8-1c63e36d5e62

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-17

## Tags
attack.persistence

## Description
Detects PowerShell creating a binary executable or a script file.

## References
https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution

## False Positives
False positives will differ depending on the environment and scripts used. Apply additional filters accordingly.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (((SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".chm" OR TgtFilePath endswithCIS ".cmd" OR TgtFilePath endswithCIS ".com" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".jar" OR TgtFilePath endswithCIS ".js" OR TgtFilePath endswithCIS ".ocx" OR TgtFilePath endswithCIS ".scr" OR TgtFilePath endswithCIS ".sys" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs" OR TgtFilePath endswithCIS ".wsf")) AND (NOT (((TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe") AND TgtFilePath startswithCIS "C:\Windows\Temp\") OR (TgtFilePath containsCIS "\AppData\Local\Temp\" AND (TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe") AND TgtFilePath startswithCIS "C:\Users\")))))

```