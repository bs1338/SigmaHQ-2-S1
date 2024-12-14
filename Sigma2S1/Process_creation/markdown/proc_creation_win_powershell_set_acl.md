# proc_creation_win_powershell_set_acl

## Title
PowerShell Script Change Permission Via Set-Acl

## ID
bdeb2cff-af74-4094-8426-724dc937f20a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-18

## Tags
attack.defense-evasion

## Description
Detects PowerShell execution to set the ACL of a file or a folder

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-5.1
https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1505.005/T1505.005.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Set-Acl " AND TgtProcCmdLine containsCIS "-AclObject " AND TgtProcCmdLine containsCIS "-Path ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```