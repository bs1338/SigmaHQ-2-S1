# proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh

## Title
SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code

## ID
36475a7d-0f6d-4dce-9b01-6aeb473bbaf1

## Author
frack113

## Date
2021-07-16

## Tags
attack.defense-evasion, attack.t1218, attack.t1216

## Description
Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1216/T1216.md
https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "\SyncAppvPublishingServer.vbs" AND TgtProcCmdLine containsCIS ";"))

```