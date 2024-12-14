# proc_creation_win_bitsadmin_download_susp_targetfolder

## Title
File Download Via Bitsadmin To A Suspicious Target Folder

## ID
2ddef153-167b-4e89-86b6-757a9e65dcac

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file to a suspicious target folder

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /transfer " OR TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND (TgtProcCmdLine containsCIS ":\Perflogs" OR TgtProcCmdLine containsCIS ":\ProgramData\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "%ProgramData%" OR TgtProcCmdLine containsCIS "%public%") AND TgtProcImagePath endswithCIS "\bitsadmin.exe"))

```