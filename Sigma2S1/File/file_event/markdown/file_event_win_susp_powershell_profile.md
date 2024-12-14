# file_event_win_susp_powershell_profile

## Title
PowerShell Profile Modification

## ID
b5b78988-486d-4a80-b991-930eff3ff8bf

## Author
HieuTT35, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-24

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.013

## Description
Detects the creation or modification of a powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence

## References
https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
https://persistence-info.github.io/Data/powershellprofile.html

## False Positives
System administrator creating Powershell profile manually

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS "\Microsoft.PowerShell_profile.ps1" OR TgtFilePath endswithCIS "\PowerShell\profile.ps1" OR TgtFilePath endswithCIS "\Program Files\PowerShell\7-preview\profile.ps1" OR TgtFilePath endswithCIS "\Program Files\PowerShell\7\profile.ps1" OR TgtFilePath endswithCIS "\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" OR TgtFilePath endswithCIS "\WindowsPowerShell\profile.ps1"))

```