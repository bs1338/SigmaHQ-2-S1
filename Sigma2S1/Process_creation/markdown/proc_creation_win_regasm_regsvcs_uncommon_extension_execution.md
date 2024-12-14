# proc_creation_win_regasm_regsvcs_uncommon_extension_execution

## Title
Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension

## ID
e9f8f8cc-07cc-4e81-b724-f387db9175e4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-13

## Tags
attack.defense-evasion, attack.t1218.009

## Description
Detects potentially suspicious execution of the Regasm/Regsvcs utilities with an uncommon extension.

## References
https://www.fortiguard.com/threat-signal-report/4718?s=09
https://lolbas-project.github.io/lolbas/Binaries/Regasm/
https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".dat" OR TgtProcCmdLine containsCIS ".gif" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".txt") AND (TgtProcImagePath endswithCIS "\Regsvcs.exe" OR TgtProcImagePath endswithCIS "\Regasm.exe")))

```