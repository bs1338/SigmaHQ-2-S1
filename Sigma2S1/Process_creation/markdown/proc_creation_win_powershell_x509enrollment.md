# proc_creation_win_powershell_x509enrollment

## Title
Suspicious X509Enrollment - Process Creation

## ID
114de787-4eb2-48cc-abdb-c0b449f93ea4

## Author
frack113

## Date
2022-12-23

## Tags
attack.defense-evasion, attack.t1553.004

## Description
Detect use of X509Enrollment

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=42
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=41
https://learn.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.cx509enrollmentwebclassfactoryclass?view=hpc-sdk-5.1.6115

## False Positives
Legitimate administrative script

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "X509Enrollment.CBinaryConverter" OR TgtProcCmdLine containsCIS "884e2002-217d-11da-b2a4-000e7bbb2b09"))

```