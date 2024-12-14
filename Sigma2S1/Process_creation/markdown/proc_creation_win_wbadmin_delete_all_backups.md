# proc_creation_win_wbadmin_delete_all_backups

## Title
All Backups Deleted Via Wbadmin.EXE

## ID
639c9081-f482-47d3-a0bd-ddee3d4ecd76

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-13

## Tags
attack.impact, attack.t1490

## Description
Detects the deletion of all backups or system state backups via "wbadmin.exe".
This technique is used by numerous ransomware families and actors.
This may only be successful on server platforms that have Windows Backup enabled.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell
https://github.com/albertzsigovits/malware-notes/blob/558898932c1579ff589290092a2c8febefc3a4c9/Ransomware/Lockbit.md
https://www.sentinelone.com/labs/ranzy-ransomware-better-encryption-among-new-features-of-thunderx-derivative/
https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/ransomware-report-avaddon-and-new-techniques-emerge-industrial-sector-targeted
https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/b/lockbit-attempts-to-stay-afloat-with-a-new-version/technical-appendix-lockbit-ng-dev-analysis.pdf
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-delete-systemstatebackup

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "keepVersions:0" AND (TgtProcCmdLine containsCIS "delete" AND TgtProcCmdLine containsCIS "backup")) AND TgtProcImagePath endswithCIS "\wbadmin.exe"))

```