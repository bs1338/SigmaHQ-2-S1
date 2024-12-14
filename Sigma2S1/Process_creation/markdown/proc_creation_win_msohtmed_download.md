# proc_creation_win_msohtmed_download

## Title
Arbitrary File Download Via MSOHTMED.EXE

## ID
459f2f98-397b-4a4a-9f47-6a5ec2f1c69d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of "MSOHTMED" to download arbitrary files

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/238/files

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "ftp://" OR TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://") AND TgtProcImagePath endswithCIS "\MSOHTMED.exe"))

```