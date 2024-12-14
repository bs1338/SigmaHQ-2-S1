# proc_creation_win_sqlcmd_veeam_db_recon

## Title
Veeam Backup Database Suspicious Query

## ID
696bfb54-227e-4602-ac5b-30d9d2053312

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-04

## Tags
attack.collection, attack.t1005

## Description
Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information.

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "BackupRepositories" OR TgtProcCmdLine containsCIS "Backups" OR TgtProcCmdLine containsCIS "Credentials" OR TgtProcCmdLine containsCIS "HostCreds" OR TgtProcCmdLine containsCIS "SmbFileShares" OR TgtProcCmdLine containsCIS "Ssh_creds" OR TgtProcCmdLine containsCIS "VSphereInfo") AND ((TgtProcCmdLine containsCIS "VeeamBackup" AND TgtProcCmdLine containsCIS "From ") AND TgtProcImagePath endswithCIS "\sqlcmd.exe")))

```