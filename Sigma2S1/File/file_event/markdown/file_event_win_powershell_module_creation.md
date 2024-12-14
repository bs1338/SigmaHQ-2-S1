# file_event_win_powershell_module_creation

## Title
PowerShell Module File Created

## ID
e36941d0-c0f0-443f-bc6f-cb2952eb69ea

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-09

## Tags
attack.persistence

## Description
Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc.

## References
Internal Research
https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

## False Positives
Likely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe") AND (TgtFilePath containsCIS "\WindowsPowerShell\Modules\" OR TgtFilePath containsCIS "\PowerShell\7\Modules\")))

```