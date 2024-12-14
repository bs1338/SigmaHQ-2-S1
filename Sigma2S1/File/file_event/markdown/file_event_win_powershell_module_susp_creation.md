# file_event_win_powershell_module_susp_creation

## Title
Potential Suspicious PowerShell Module File Created

## ID
e8a52bbd-bced-459f-bd93-64db45ce7657

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-09

## Tags
attack.persistence

## Description
Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.

## References
Internal Research
https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3

## False Positives
False positive rate will vary depending on the environments. Additional filters might be required to make this logic usable in production.

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath = "*\WindowsPowerShell\Modules\*\.ps" OR TgtFilePath = "*\WindowsPowerShell\Modules\*\.dll"))

```