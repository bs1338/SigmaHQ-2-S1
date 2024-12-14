# proc_creation_win_sysinternals_adexplorer_execution

## Title
Active Directory Database Snapshot Via ADExplorer

## ID
9212f354-7775-4e28-9c9f-8f0a4544e664

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-14

## Tags
attack.credential-access, attack.t1552.001, attack.t1003.003

## Description
Detects the execution of Sysinternals ADExplorer with the "-snapshot" flag in order to save a local copy of the active directory database.

## References
https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "snapshot" AND TgtProcImagePath endswithCIS "\ADExplorer.exe"))

```