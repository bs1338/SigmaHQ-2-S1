# proc_creation_win_wget_download_susp_file_sharing_domains

## Title
Suspicious File Download From File Sharing Domain Via Wget.EXE

## ID
a0d7e4d2-bede-4141-8896-bc6e237e977c

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-05

## Tags
attack.execution

## Description
Detects potentially suspicious file downloads from file sharing domains using wget.exe

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers
https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".ps1" OR TgtProcCmdLine endswithCIS ".ps1'" OR TgtProcCmdLine endswithCIS ".ps1\"" OR TgtProcCmdLine endswithCIS ".dat" OR TgtProcCmdLine endswithCIS ".dat'" OR TgtProcCmdLine endswithCIS ".dat\"" OR TgtProcCmdLine endswithCIS ".msi" OR TgtProcCmdLine endswithCIS ".msi'" OR TgtProcCmdLine endswithCIS ".msi\"" OR TgtProcCmdLine endswithCIS ".bat" OR TgtProcCmdLine endswithCIS ".bat'" OR TgtProcCmdLine endswithCIS ".bat\"" OR TgtProcCmdLine endswithCIS ".exe" OR TgtProcCmdLine endswithCIS ".exe'" OR TgtProcCmdLine endswithCIS ".exe\"" OR TgtProcCmdLine endswithCIS ".vbs" OR TgtProcCmdLine endswithCIS ".vbs'" OR TgtProcCmdLine endswithCIS ".vbs\"" OR TgtProcCmdLine endswithCIS ".vbe" OR TgtProcCmdLine endswithCIS ".vbe'" OR TgtProcCmdLine endswithCIS ".vbe\"" OR TgtProcCmdLine endswithCIS ".hta" OR TgtProcCmdLine endswithCIS ".hta'" OR TgtProcCmdLine endswithCIS ".hta\"" OR TgtProcCmdLine endswithCIS ".dll" OR TgtProcCmdLine endswithCIS ".dll'" OR TgtProcCmdLine endswithCIS ".dll\"" OR TgtProcCmdLine endswithCIS ".psm1" OR TgtProcCmdLine endswithCIS ".psm1'" OR TgtProcCmdLine endswithCIS ".psm1\"") AND (TgtProcCmdLine RegExp "\\s-O\\s" OR TgtProcCmdLine containsCIS "--output-document") AND TgtProcCmdLine containsCIS "http" AND TgtProcImagePath endswithCIS "\wget.exe" AND (TgtProcCmdLine containsCIS ".githubusercontent.com" OR TgtProcCmdLine containsCIS "anonfiles.com" OR TgtProcCmdLine containsCIS "cdn.discordapp.com" OR TgtProcCmdLine containsCIS "ddns.net" OR TgtProcCmdLine containsCIS "dl.dropboxusercontent.com" OR TgtProcCmdLine containsCIS "ghostbin.co" OR TgtProcCmdLine containsCIS "glitch.me" OR TgtProcCmdLine containsCIS "gofile.io" OR TgtProcCmdLine containsCIS "hastebin.com" OR TgtProcCmdLine containsCIS "mediafire.com" OR TgtProcCmdLine containsCIS "mega.nz" OR TgtProcCmdLine containsCIS "onrender.com" OR TgtProcCmdLine containsCIS "pages.dev" OR TgtProcCmdLine containsCIS "paste.ee" OR TgtProcCmdLine containsCIS "pastebin.com" OR TgtProcCmdLine containsCIS "pastebin.pl" OR TgtProcCmdLine containsCIS "pastetext.net" OR TgtProcCmdLine containsCIS "pixeldrain.com" OR TgtProcCmdLine containsCIS "privatlab.com" OR TgtProcCmdLine containsCIS "privatlab.net" OR TgtProcCmdLine containsCIS "send.exploit.in" OR TgtProcCmdLine containsCIS "sendspace.com" OR TgtProcCmdLine containsCIS "storage.googleapis.com" OR TgtProcCmdLine containsCIS "storjshare.io" OR TgtProcCmdLine containsCIS "supabase.co" OR TgtProcCmdLine containsCIS "temp.sh" OR TgtProcCmdLine containsCIS "transfer.sh" OR TgtProcCmdLine containsCIS "trycloudflare.com" OR TgtProcCmdLine containsCIS "ufile.io" OR TgtProcCmdLine containsCIS "w3spaces.com" OR TgtProcCmdLine containsCIS "workers.dev")))

```