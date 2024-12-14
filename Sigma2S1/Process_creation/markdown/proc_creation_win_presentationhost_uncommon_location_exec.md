# proc_creation_win_presentationhost_uncommon_location_exec

## Title
XBAP Execution From Uncommon Locations Via PresentationHost.EXE

## ID
d22e2925-cfd8-463f-96f6-89cec9d9bc5f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-01

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects the execution of ".xbap" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious ".xbap" files any bypass AWL


## References
https://lolbas-project.github.io/lolbas/Binaries/Presentationhost/

## False Positives
Legitimate ".xbap" being executed via "PresentationHost"

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".xbap" AND TgtProcImagePath endswithCIS "\presentationhost.exe") AND (NOT (TgtProcCmdLine containsCIS " C:\Windows\" OR TgtProcCmdLine containsCIS " C:\Program Files"))))

```