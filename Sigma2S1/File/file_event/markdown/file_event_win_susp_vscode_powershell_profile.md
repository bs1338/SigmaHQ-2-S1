# file_event_win_susp_vscode_powershell_profile

## Title
VsCode Powershell Profile Modification

## ID
3a9fa2ec-30bc-4ebd-b49e-7c9cff225502

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-24

## Tags
attack.persistence, attack.privilege-escalation, attack.t1546.013

## Description
Detects the creation or modification of a vscode related powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2

## False Positives
Legitimate use of the profile by developers or administrators

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\Microsoft.VSCode_profile.ps1")

```