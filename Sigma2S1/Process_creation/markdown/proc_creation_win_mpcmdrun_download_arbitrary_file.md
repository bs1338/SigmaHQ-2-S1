# proc_creation_win_mpcmdrun_download_arbitrary_file

## Title
File Download Via Windows Defender MpCmpRun.EXE

## ID
46123129-1024-423e-9fae-43af4a0fa9a5

## Author
Matthew Matchen

## Date
2020-09-04

## Tags
attack.defense-evasion, attack.t1218, attack.command-and-control, attack.t1105

## Description
Detects the use of Windows Defender MpCmdRun.EXE to download files

## References
https://web.archive.org/web/20200903194959/https://twitter.com/djmtshepana/status/1301608169496612866
https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "DownloadFile" AND TgtProcCmdLine containsCIS "url") AND (TgtProcImagePath endswithCIS "\MpCmdRun.exe" OR TgtProcCmdLine containsCIS "MpCmdRun.exe" OR TgtProcDisplayName = "Microsoft Malware Protection Command Line Utility")))

```