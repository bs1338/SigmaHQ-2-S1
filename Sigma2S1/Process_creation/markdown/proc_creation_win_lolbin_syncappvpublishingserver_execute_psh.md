# proc_creation_win_lolbin_syncappvpublishingserver_execute_psh

## Title
SyncAppvPublishingServer Execute Arbitrary PowerShell Code

## ID
fbd7c32d-db2a-4418-b92c-566eb8911133

## Author
frack113

## Date
2021-07-12

## Tags
attack.defense-evasion, attack.t1218

## Description
Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md
https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/

## False Positives
App-V clients

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\"n; " AND TgtProcImagePath endswithCIS "\SyncAppvPublishingServer.exe"))

```