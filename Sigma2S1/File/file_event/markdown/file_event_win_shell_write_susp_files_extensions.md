# file_event_win_shell_write_susp_files_extensions

## Title
Windows Binaries Write Suspicious Extensions

## ID
b8fd0e93-ff58-4cbd-8f48-1c114e342e62

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-12

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects Windows executables that write files with suspicious extensions

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((((SrcProcImagePath endswithCIS "\csrss.exe" OR SrcProcImagePath endswithCIS "\lsass.exe" OR SrcProcImagePath endswithCIS "\RuntimeBroker.exe" OR SrcProcImagePath endswithCIS "\sihost.exe" OR SrcProcImagePath endswithCIS "\smss.exe" OR SrcProcImagePath endswithCIS "\wininit.exe" OR SrcProcImagePath endswithCIS "\winlogon.exe") AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".iso" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".txt" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs")) OR ((SrcProcImagePath endswithCIS "\dllhost.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\svchost.exe") AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".iso" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs"))) AND (NOT ((SrcProcImagePath = "C:\Windows\System32\dllhost.exe" AND (TgtFilePath containsCIS ":\Users\" AND TgtFilePath containsCIS "\AppData\Local\Temp\__PSScriptPolicyTest_") AND TgtFilePath endswithCIS ".ps1") OR (SrcProcImagePath = "C:\Windows\system32\svchost.exe" AND (TgtFilePath containsCIS "C:\Windows\System32\GroupPolicy\DataStore\" AND TgtFilePath containsCIS "\sysvol\" AND TgtFilePath containsCIS "\Policies\" AND TgtFilePath containsCIS "\Machine\Scripts\Startup\") AND (TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".bat"))))))

```