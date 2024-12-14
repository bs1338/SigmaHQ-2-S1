# file_event_win_powershell_module_uncommon_creation

## Title
PowerShell Module File Created By Non-PowerShell Process

## ID
e3845023-ca9a-4024-b2b2-5422156d5527

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-09

## Tags
attack.persistence

## Description
Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc. by a non-PowerShell process

## References
Internal Research
https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\WindowsPowerShell\Modules\" OR TgtFilePath containsCIS "\PowerShell\7\Modules\") AND (NOT (SrcProcImagePath endswithCIS ":\Program Files\PowerShell\7-preview\pwsh.exe" OR SrcProcImagePath endswithCIS ":\Program Files\PowerShell\7\pwsh.exe" OR SrcProcImagePath endswithCIS ":\Windows\System32\poqexec.exe" OR SrcProcImagePath endswithCIS ":\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" OR SrcProcImagePath endswithCIS ":\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" OR SrcProcImagePath endswithCIS ":\Windows\SysWOW64\poqexec.exe" OR SrcProcImagePath endswithCIS ":\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe" OR SrcProcImagePath endswithCIS ":\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"))))

```