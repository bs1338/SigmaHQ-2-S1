# proc_creation_win_mspub_download

## Title
Arbitrary File Download Via MSPUB.EXE

## ID
3b3c7f55-f771-4dd6-8a6e-08d057a17caf

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/238/files

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ftp://" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\MSPUB.exe"))

```