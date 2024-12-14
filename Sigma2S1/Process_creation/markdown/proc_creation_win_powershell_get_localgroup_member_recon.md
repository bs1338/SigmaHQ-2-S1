# proc_creation_win_powershell_get_localgroup_member_recon

## Title
Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet

## ID
c8a180d6-47a3-4345-a609-53f9c3d834fc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-10

## Tags
attack.discovery, attack.t1087.001

## Description
Detects suspicious reconnaissance command line activity on Windows systems using the PowerShell Get-LocalGroupMember Cmdlet

## References
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Get-LocalGroupMember " AND (TgtProcCmdLine containsCIS "domain admins" OR TgtProcCmdLine containsCIS " administrator" OR TgtProcCmdLine containsCIS " administrateur" OR TgtProcCmdLine containsCIS "enterprise admins" OR TgtProcCmdLine containsCIS "Exchange Trusted Subsystem" OR TgtProcCmdLine containsCIS "Remote Desktop Users" OR TgtProcCmdLine containsCIS "Utilisateurs du Bureau Ã  distance" OR TgtProcCmdLine containsCIS "Usuarios de escritorio remoto")))

```