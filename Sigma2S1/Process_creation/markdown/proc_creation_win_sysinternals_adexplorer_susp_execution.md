# proc_creation_win_sysinternals_adexplorer_susp_execution

## Title
Suspicious Active Directory Database Snapshot Via ADExplorer

## ID
ef61af62-bc74-4f58-b49b-626448227652

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-03-14

## Tags
attack.credential-access, attack.t1552.001, attack.t1003.003

## Description
Detects the execution of Sysinternals ADExplorer with the "-snapshot" flag in order to save a local copy of the active directory database to a suspicious directory.

## References
https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "snapshot" AND TgtProcImagePath endswithCIS "\ADExplorer.exe" AND (TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\AppData\" OR TgtProcCmdLine containsCIS "\Windows\Temp\")))

```