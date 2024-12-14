# proc_creation_win_gup_download

## Title
File Download Using Notepad++ GUP Utility

## ID
44143844-0631-49ab-97a0-96387d6b2d7c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-10

## Tags
attack.command-and-control, attack.t1105

## Description
Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files.

## References
https://twitter.com/nas_bench/status/1535322182863179776

## False Positives
Other parent processes other than notepad++ using GUP that are not currently identified

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -unzipTo " AND TgtProcCmdLine containsCIS "http") AND TgtProcImagePath endswithCIS "\GUP.exe") AND (NOT SrcProcImagePath endswithCIS "\notepad++.exe")))

```