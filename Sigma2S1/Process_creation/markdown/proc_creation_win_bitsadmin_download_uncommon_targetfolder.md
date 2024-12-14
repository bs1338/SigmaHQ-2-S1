# proc_creation_win_bitsadmin_download_uncommon_targetfolder

## Title
File Download Via Bitsadmin To An Uncommon Target Folder

## ID
6e30c82f-a9f8-4aab-b79c-7c12bce6f248

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file to uncommon target folder

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /transfer " OR TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND (TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "C:\Windows\Temp\") AND TgtProcImagePath endswithCIS "\bitsadmin.exe"))

```