# proc_creation_win_sqlcmd_veeam_dump

## Title
VeeamBackup Database Credentials Dump Via Sqlcmd.EXE

## ID
b57ba453-b384-4ab9-9f40-1038086b4e53

## Author
frack113

## Date
2021-12-20

## Tags
attack.collection, attack.t1005

## Description
Detects dump of credentials in VeeamBackup dbo

## References
https://thedfirreport.com/2021/12/13/diavol-ransomware/
https://forums.veeam.com/veeam-backup-replication-f2/recover-esxi-password-in-veeam-t34630.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "SELECT" AND TgtProcCmdLine containsCIS "TOP" AND TgtProcCmdLine containsCIS "[VeeamBackup].[dbo].[Credentials]") AND TgtProcImagePath endswithCIS "\sqlcmd.exe"))

```