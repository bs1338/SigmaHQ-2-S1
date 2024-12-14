# proc_creation_win_lolbin_customshellhost

## Title
Suspicious CustomShellHost Execution

## ID
84b14121-9d14-416e-800b-f3b829c5a14d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects the execution of CustomShellHost binary where the child isn't located in 'C:\Windows\explorer.exe'

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/180
https://lolbas-project.github.io/lolbas/Binaries/CustomShellHost/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\CustomShellHost.exe" AND (NOT TgtProcImagePath = "C:\Windows\explorer.exe")))

```