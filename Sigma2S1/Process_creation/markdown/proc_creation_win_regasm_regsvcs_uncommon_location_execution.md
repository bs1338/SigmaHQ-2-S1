# proc_creation_win_regasm_regsvcs_uncommon_location_execution

## Title
Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location

## ID
cc368ed0-2411-45dc-a222-510ace303cb2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-25

## Tags
attack.defense-evasion, attack.t1218.009

## Description
Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location

## References
https://www.fortiguard.com/threat-signal-report/4718?s=09
https://lolbas-project.github.io/lolbas/Binaries/Regasm/
https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\" OR TgtProcCmdLine containsCIS "\PerfLogs\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\Windows\Temp\") AND (TgtProcImagePath endswithCIS "\Regsvcs.exe" OR TgtProcImagePath endswithCIS "\Regasm.exe")))

```