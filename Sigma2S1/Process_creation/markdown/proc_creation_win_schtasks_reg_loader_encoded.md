# proc_creation_win_schtasks_reg_loader_encoded

## Title
Scheduled Task Executing Encoded Payload from Registry

## ID
c4eeeeae-89f4-43a7-8b48-8d1bdfa66c78

## Author
pH-T (Nextron Systems), @Kostastsale, @TheDFIRReport, X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-02-12

## Tags
attack.execution, attack.persistence, attack.t1053.005, attack.t1059.001

## Description
Detects the creation of a schtask that potentially executes a base64 encoded payload stored in the Windows Registry using PowerShell.

## References
https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/Create" AND (TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "encodedcommand") AND (TgtProcCmdLine containsCIS "Get-ItemProperty" OR TgtProcCmdLine containsCIS " gp ") AND (TgtProcCmdLine containsCIS "HKCU:" OR TgtProcCmdLine containsCIS "HKLM:" OR TgtProcCmdLine containsCIS "registry::" OR TgtProcCmdLine containsCIS "HKEY_") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```