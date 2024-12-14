# proc_creation_win_powershell_hide_services_via_set_service

## Title
Abuse of Service Permissions to Hide Services Via Set-Service

## ID
514e4c3a-c77d-4cde-a00f-046425e2301e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-17

## Tags
attack.persistence, attack.defense-evasion, attack.privilege-escalation, attack.t1574.011

## Description
Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)

## References
https://twitter.com/Alh4zr3d/status/1580925761996828672
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-7.2

## False Positives
Rare intended use of hidden services

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-SecurityDescriptorSddl " OR TgtProcCmdLine containsCIS "-sd ") AND TgtProcImagePath endswithCIS "\pwsh.exe" AND (TgtProcCmdLine containsCIS "Set-Service " AND TgtProcCmdLine containsCIS "DCLCWPDTSD")))

```