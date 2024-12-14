# proc_creation_win_bitsadmin_download_susp_extensions

## Title
File With Suspicious Extension Downloaded Via Bitsadmin

## ID
5b80a791-ad9b-4b75-bcc1-ad4e1e89c200

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file with a suspicious extension

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".7z" OR TgtProcCmdLine containsCIS ".asax" OR TgtProcCmdLine containsCIS ".ashx" OR TgtProcCmdLine containsCIS ".asmx" OR TgtProcCmdLine containsCIS ".asp" OR TgtProcCmdLine containsCIS ".aspx" OR TgtProcCmdLine containsCIS ".bat" OR TgtProcCmdLine containsCIS ".cfm" OR TgtProcCmdLine containsCIS ".cgi" OR TgtProcCmdLine containsCIS ".chm" OR TgtProcCmdLine containsCIS ".cmd" OR TgtProcCmdLine containsCIS ".dll" OR TgtProcCmdLine containsCIS ".gif" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".jsp" OR TgtProcCmdLine containsCIS ".jspx" OR TgtProcCmdLine containsCIS ".log" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".ps1" OR TgtProcCmdLine containsCIS ".psm1" OR TgtProcCmdLine containsCIS ".rar" OR TgtProcCmdLine containsCIS ".scf" OR TgtProcCmdLine containsCIS ".sct" OR TgtProcCmdLine containsCIS ".txt" OR TgtProcCmdLine containsCIS ".vbe" OR TgtProcCmdLine containsCIS ".vbs" OR TgtProcCmdLine containsCIS ".war" OR TgtProcCmdLine containsCIS ".wsf" OR TgtProcCmdLine containsCIS ".wsh" OR TgtProcCmdLine containsCIS ".xll" OR TgtProcCmdLine containsCIS ".zip") AND (TgtProcCmdLine containsCIS " /transfer " OR TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND TgtProcImagePath endswithCIS "\bitsadmin.exe"))

```