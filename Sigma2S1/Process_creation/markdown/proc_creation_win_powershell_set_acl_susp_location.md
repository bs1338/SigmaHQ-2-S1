# proc_creation_win_powershell_set_acl_susp_location

## Title
PowerShell Set-Acl On Windows Folder

## ID
0944e002-e3f6-4eb5-bf69-3a3067b53d73

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-18

## Tags
attack.defense-evasion

## Description
Detects PowerShell scripts to set the ACL to a file in the Windows folder

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-5.1
https://github.com/redcanaryco/atomic-red-team/blob/74438b0237d141ee9c99747976447dc884cb1a39/atomics/T1505.005/T1505.005.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Set-Acl " AND TgtProcCmdLine containsCIS "-AclObject ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "-Path \"C:\Windows" OR TgtProcCmdLine containsCIS "-Path 'C:\Windows" OR TgtProcCmdLine containsCIS "-Path %windir%" OR TgtProcCmdLine containsCIS "-Path $env:windir") AND (TgtProcCmdLine containsCIS "FullControl" OR TgtProcCmdLine containsCIS "Allow")))

```