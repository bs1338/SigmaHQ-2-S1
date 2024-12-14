# proc_creation_win_powershell_cl_invocation

## Title
Potential Process Execution Proxy Via CL_Invocation.ps1

## ID
a0459f02-ac51-4c09-b511-b8c9203fc429

## Author
Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova

## Date
2020-10-14

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects calls to "SyncInvoke" that is part of the "CL_Invocation.ps1" script to proxy execution using "System.Diagnostics.Process"

## References
https://lolbas-project.github.io/lolbas/Scripts/Cl_invocation/
https://twitter.com/bohops/status/948061991012327424

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "SyncInvoke ")

```