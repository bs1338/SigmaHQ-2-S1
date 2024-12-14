# proc_creation_win_susp_download_office_domain

## Title
Suspicious Download from Office Domain

## ID
00d49ed5-4491-4271-a8db-650a4ef6f8c1

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-12-27

## Tags
attack.command-and-control, attack.t1105, attack.t1608

## Description
Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents

## References
https://twitter.com/an0n_r0/status/1474698356635193346?s=12
https://twitter.com/mrd0x/status/1475085452784844803?s=12

## False Positives
Scripts or tools that download attachments from these domains (OneNote, Outlook 365)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "https://attachment.outlook.live.net/owa/" OR TgtProcCmdLine containsCIS "https://onenoteonlinesync.onenote.com/onenoteonlinesync/") AND ((TgtProcImagePath endswithCIS "\curl.exe" OR TgtProcImagePath endswithCIS "\wget.exe") OR (TgtProcCmdLine containsCIS "Invoke-WebRequest" OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "curl " OR TgtProcCmdLine containsCIS "wget " OR TgtProcCmdLine containsCIS "Start-BitsTransfer" OR TgtProcCmdLine containsCIS ".DownloadFile(" OR TgtProcCmdLine containsCIS ".DownloadString("))))

```