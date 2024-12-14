# proc_creation_win_mssql_sqltoolsps_susp_execution

## Title
SQL Client Tools PowerShell Session Detection

## ID
a746c9b8-a2fb-4ee5-a428-92bee9e99060

## Author
Agro (@agro_sev) oscd.communitly

## Date
2020-10-13

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1127

## Description
This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio.
Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.


## References
https://github.com/LOLBAS-Project/LOLBAS/blob/8283d8d91552213ded165fd36deb6cb9534cb443/yml/OtherMSBinaries/Sqltoolsps.yml
https://twitter.com/pabraeken/status/993298228840992768

## False Positives
Direct PS command execution through SQLToolsPS.exe is uncommon, childprocess sqltoolsps.exe spawned by smss.exe is a legitimate action.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\sqltoolsps.exe" OR SrcProcImagePath endswithCIS "\sqltoolsps.exe") AND (NOT SrcProcImagePath endswithCIS "\smss.exe")))

```