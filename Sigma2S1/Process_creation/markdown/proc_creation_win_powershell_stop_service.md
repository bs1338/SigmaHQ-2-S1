# proc_creation_win_powershell_stop_service

## Title
Stop Windows Service Via PowerShell Stop-Service

## ID
c49c5062-0966-4170-9efd-9968c913a6cf

## Author
Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-05

## Tags
attack.impact, attack.t1489

## Description
Detects the stopping of a Windows service via the PowerShell Cmdlet "Stop-Service"

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/stop-service?view=powershell-7.4

## False Positives
There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Stop-Service " AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```