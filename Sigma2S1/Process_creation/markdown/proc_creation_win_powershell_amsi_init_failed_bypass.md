# proc_creation_win_powershell_amsi_init_failed_bypass

## Title
Potential AMSI Bypass Via .NET Reflection

## ID
30edb182-aa75-42c0-b0a9-e998bb29067c

## Author
Markus Neis, @Kostastsale

## Date
2018-08-17

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning

## References
https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/
https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "System.Management.Automation.AmsiUtils" AND TgtProcCmdLine containsCIS "amsiInitFailed") OR (TgtProcCmdLine containsCIS "[Ref].Assembly.GetType" AND TgtProcCmdLine containsCIS "SetValue($null,$true)" AND TgtProcCmdLine containsCIS "NonPublic,Static")))

```