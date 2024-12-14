# proc_creation_win_bitsadmin_download_direct_ip

## Title
Suspicious Download From Direct IP Via Bitsadmin

## ID
99c840f2-2012-46fd-9141-c761987550ef

## Author
Florian Roth (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file using an URL that contains an IP

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "://1" OR TgtProcCmdLine containsCIS "://2" OR TgtProcCmdLine containsCIS "://3" OR TgtProcCmdLine containsCIS "://4" OR TgtProcCmdLine containsCIS "://5" OR TgtProcCmdLine containsCIS "://6" OR TgtProcCmdLine containsCIS "://7" OR TgtProcCmdLine containsCIS "://8" OR TgtProcCmdLine containsCIS "://9") AND (TgtProcCmdLine containsCIS " /transfer " OR TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND TgtProcImagePath endswithCIS "\bitsadmin.exe") AND (NOT TgtProcCmdLine containsCIS "://7-")))

```