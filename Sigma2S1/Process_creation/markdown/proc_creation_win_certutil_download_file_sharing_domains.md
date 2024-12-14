# proc_creation_win_certutil_download_file_sharing_domains

## Title
Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE

## ID
42a5f1e7-9603-4f6d-97ae-3f37d130d794

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1027

## Description
Detects the execution of certutil with certain flags that allow the utility to download files from file-sharing websites.

## References
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
https://forensicitguy.github.io/agenttesla-vba-certutil-download/
https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
https://twitter.com/egre55/status/1087685529016193025
https://lolbas-project.github.io/lolbas/Binaries/Certutil/
https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "urlcache " OR TgtProcCmdLine containsCIS "verifyctl ") AND (TgtProcCmdLine containsCIS ".githubusercontent.com" OR TgtProcCmdLine containsCIS "anonfiles.com" OR TgtProcCmdLine containsCIS "cdn.discordapp.com" OR TgtProcCmdLine containsCIS "ddns.net" OR TgtProcCmdLine containsCIS "dl.dropboxusercontent.com" OR TgtProcCmdLine containsCIS "ghostbin.co" OR TgtProcCmdLine containsCIS "glitch.me" OR TgtProcCmdLine containsCIS "gofile.io" OR TgtProcCmdLine containsCIS "hastebin.com" OR TgtProcCmdLine containsCIS "mediafire.com" OR TgtProcCmdLine containsCIS "mega.nz" OR TgtProcCmdLine containsCIS "onrender.com" OR TgtProcCmdLine containsCIS "pages.dev" OR TgtProcCmdLine containsCIS "paste.ee" OR TgtProcCmdLine containsCIS "pastebin.com" OR TgtProcCmdLine containsCIS "pastebin.pl" OR TgtProcCmdLine containsCIS "pastetext.net" OR TgtProcCmdLine containsCIS "privatlab.com" OR TgtProcCmdLine containsCIS "privatlab.net" OR TgtProcCmdLine containsCIS "send.exploit.in" OR TgtProcCmdLine containsCIS "sendspace.com" OR TgtProcCmdLine containsCIS "storage.googleapis.com" OR TgtProcCmdLine containsCIS "storjshare.io" OR TgtProcCmdLine containsCIS "supabase.co" OR TgtProcCmdLine containsCIS "temp.sh" OR TgtProcCmdLine containsCIS "transfer.sh" OR TgtProcCmdLine containsCIS "trycloudflare.com" OR TgtProcCmdLine containsCIS "ufile.io" OR TgtProcCmdLine containsCIS "w3spaces.com" OR TgtProcCmdLine containsCIS "workers.dev") AND TgtProcImagePath endswithCIS "\certutil.exe"))

```