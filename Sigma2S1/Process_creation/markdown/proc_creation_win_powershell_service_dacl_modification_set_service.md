# proc_creation_win_powershell_service_dacl_modification_set_service

## Title
Suspicious Service DACL Modification Via Set-Service Cmdlet

## ID
a95b9b42-1308-4735-a1af-abb1c5e6f5ac

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-18

## Tags
attack.persistence, attack.t1543.003

## Description
Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable

## References
https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
https://learn.microsoft.com/pt-br/windows/win32/secauthz/sid-strings

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\pwsh.exe" AND (TgtProcCmdLine containsCIS "-SecurityDescriptorSddl " OR TgtProcCmdLine containsCIS "-sd ") AND ((TgtProcCmdLine containsCIS ";;;IU" OR TgtProcCmdLine containsCIS ";;;SU" OR TgtProcCmdLine containsCIS ";;;BA" OR TgtProcCmdLine containsCIS ";;;SY" OR TgtProcCmdLine containsCIS ";;;WD") AND (TgtProcCmdLine containsCIS "Set-Service " AND TgtProcCmdLine containsCIS "D;;"))))

```