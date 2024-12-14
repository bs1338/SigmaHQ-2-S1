# proc_creation_win_wbadmin_restore_sensitive_files

## Title
Sensitive File Recovery From Backup Via Wbadmin.EXE

## ID
84972c80-251c-4c3a-9079-4f00aad93938

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
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "\config\SAM" OR TgtProcCmdLine containsCIS "\config\SECURITY" OR TgtProcCmdLine containsCIS "\config\SYSTEM" OR TgtProcCmdLine containsCIS "\Windows\NTDS\NTDS.dit") AND (TgtProcCmdLine containsCIS " recovery" AND TgtProcCmdLine containsCIS "recoveryTarget" AND TgtProcCmdLine containsCIS "itemtype:File")) AND TgtProcImagePath endswithCIS "\wbadmin.exe"))

```