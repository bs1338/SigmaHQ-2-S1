# proc_creation_win_presentationhost_download

## Title
Arbitrary File Download Via PresentationHost.EXE

## ID
b124ddf4-778d-418e-907f-6dd3fc0d31cd

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-19

## Tags
attack.defense-evasion, attack.execution, attack.t1218

## Description
Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files

## References
https://github.com/LOLBAS-Project/LOLBAS/pull/239/files

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "http://" OR TgtProcCmdLine containsCIS "https://" OR TgtProcCmdLine containsCIS "ftp://") AND TgtProcImagePath endswithCIS "\presentationhost.exe"))

```