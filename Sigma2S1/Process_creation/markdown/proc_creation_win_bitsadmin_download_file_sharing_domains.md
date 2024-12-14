# proc_creation_win_bitsadmin_download_file_sharing_domains

## Title
Suspicious Download From File-Sharing Website Via Bitsadmin

## ID
8518ed3d-f7c9-4601-a26c-f361a4256a0c

## Author
Florian Roth (Nextron Systems)

## Date
2022-06-28

## Tags
attack.defense-evasion, attack.persistence, attack.t1197, attack.s0190, attack.t1036.003

## Description
Detects usage of bitsadmin downloading a file from a suspicious domain

## References
https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
https://isc.sans.edu/diary/22264
https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

## False Positives
Some legitimate apps use this, but limited.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".githubusercontent.com" OR TgtProcCmdLine containsCIS "anonfiles.com" OR TgtProcCmdLine containsCIS "cdn.discordapp.com" OR TgtProcCmdLine containsCIS "ddns.net" OR TgtProcCmdLine containsCIS "dl.dropboxusercontent.com" OR TgtProcCmdLine containsCIS "ghostbin.co" OR TgtProcCmdLine containsCIS "glitch.me" OR TgtProcCmdLine containsCIS "gofile.io" OR TgtProcCmdLine containsCIS "hastebin.com" OR TgtProcCmdLine containsCIS "mediafire.com" OR TgtProcCmdLine containsCIS "mega.nz" OR TgtProcCmdLine containsCIS "onrender.com" OR TgtProcCmdLine containsCIS "pages.dev" OR TgtProcCmdLine containsCIS "paste.ee" OR TgtProcCmdLine containsCIS "pastebin.com" OR TgtProcCmdLine containsCIS "pastebin.pl" OR TgtProcCmdLine containsCIS "pastetext.net" OR TgtProcCmdLine containsCIS "privatlab.com" OR TgtProcCmdLine containsCIS "privatlab.net" OR TgtProcCmdLine containsCIS "send.exploit.in" OR TgtProcCmdLine containsCIS "sendspace.com" OR TgtProcCmdLine containsCIS "storage.googleapis.com" OR TgtProcCmdLine containsCIS "storjshare.io" OR TgtProcCmdLine containsCIS "supabase.co" OR TgtProcCmdLine containsCIS "temp.sh" OR TgtProcCmdLine containsCIS "transfer.sh" OR TgtProcCmdLine containsCIS "trycloudflare.com" OR TgtProcCmdLine containsCIS "ufile.io" OR TgtProcCmdLine containsCIS "w3spaces.com" OR TgtProcCmdLine containsCIS "workers.dev") AND (TgtProcCmdLine containsCIS " /transfer " OR TgtProcCmdLine containsCIS " /create " OR TgtProcCmdLine containsCIS " /addfile ") AND TgtProcImagePath endswithCIS "\bitsadmin.exe"))

```