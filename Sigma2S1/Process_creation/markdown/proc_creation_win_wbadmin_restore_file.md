# proc_creation_win_wbadmin_restore_file

## Title
File Recovery From Backup Via Wbadmin.EXE

## ID
6fe4aa1e-0531-4510-8be2-782154b73b48

## Author
Nasreddine Bencherchali (Nextron Systems), frack113

## Date
2024-05-10

## Tags
attack.impact, attack.t1490

## Description
Detects the recovery of files from backups via "wbadmin.exe".
Attackers can restore sensitive files such as NTDS.DIT or Registry Hives from backups in order to potentially extract credentials.


## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-recovery
https://lolbas-project.github.io/lolbas/Binaries/Wbadmin/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " recovery" AND TgtProcCmdLine containsCIS "recoveryTarget" AND TgtProcCmdLine containsCIS "itemtype:File") AND TgtProcImagePath endswithCIS "\wbadmin.exe"))

```