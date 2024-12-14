# proc_creation_win_mssql_sqlps_susp_execution

## Title
Detection of PowerShell Execution via Sqlps.exe

## ID
0152550d-3a26-4efd-9f0e-54a0b28ae2f3

## Author
Agro (@agro_sev) oscd.community

## Date
2020-10-10

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1127

## Description
This rule detects execution of a PowerShell code through the sqlps.exe utility, which is included in the standard set of utilities supplied with the MSSQL Server.
Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.


## References
https://learn.microsoft.com/en-us/sql/tools/sqlps-utility?view=sql-server-ver15
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqlps/
https://twitter.com/bryon_/status/975835709587075072

## False Positives
Direct PS command execution through SQLPS.exe is uncommon, childprocess sqlps.exe spawned by sqlagent.exe is a legitimate action.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\sqlps.exe" OR (TgtProcImagePath endswithCIS "\sqlps.exe" AND (NOT SrcProcImagePath endswithCIS "\sqlagent.exe"))))

```