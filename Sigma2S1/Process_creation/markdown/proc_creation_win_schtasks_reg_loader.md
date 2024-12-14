# proc_creation_win_schtasks_reg_loader

## Title
Scheduled Task Executing Payload from Registry

## ID
86588b36-c6d3-465f-9cee-8f9093e07798

## Author
X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-07-18

## Tags
attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001

## Description
Detects the creation of a schtasks that potentially executes a payload stored in the Windows Registry using PowerShell.

## References
https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "/Create" AND (TgtProcCmdLine containsCIS "Get-ItemProperty" OR TgtProcCmdLine containsCIS " gp ") AND (TgtProcCmdLine containsCIS "HKCU:" OR TgtProcCmdLine containsCIS "HKLM:" OR TgtProcCmdLine containsCIS "registry::" OR TgtProcCmdLine containsCIS "HKEY_") AND TgtProcImagePath endswithCIS "\schtasks.exe") AND (NOT (TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "encodedcommand"))))

```