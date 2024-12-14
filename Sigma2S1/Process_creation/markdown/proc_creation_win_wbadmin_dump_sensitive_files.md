# proc_creation_win_wbadmin_dump_sensitive_files

## Title
Sensitive File Dump Via Wbadmin.EXE

## ID
8b93a509-1cb8-42e1-97aa-ee24224cdc15

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2024-05-10

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects the dump of highly sensitive files such as "NTDS.DIT" and "SECURITY" hive.
Attackers can leverage the "wbadmin" utility in order to dump sensitive files that might contain credential or sensitive information.


## References
https://github.com/LOLBAS-Project/LOLBAS/blob/2cc01b01132b5c304027a658c698ae09dd6a92bf/yml/OSBinaries/Wbadmin.yml
https://lolbas-project.github.io/lolbas/Binaries/Wbadmin/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-recovery
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-backup

## False Positives
Legitimate backup operation by authorized administrators. Matches must be investigated and allowed on a case by case basis.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "start" OR TgtProcCmdLine containsCIS "backup") AND TgtProcImagePath endswithCIS "\wbadmin.exe" AND (TgtProcCmdLine containsCIS "\config\SAM" OR TgtProcCmdLine containsCIS "\config\SECURITY" OR TgtProcCmdLine containsCIS "\config\SYSTEM" OR TgtProcCmdLine containsCIS "\Windows\NTDS\NTDS.dit")))

```