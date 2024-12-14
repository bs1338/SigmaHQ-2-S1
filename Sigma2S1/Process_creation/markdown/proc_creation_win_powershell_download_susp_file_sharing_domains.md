# proc_creation_win_powershell_download_susp_file_sharing_domains

## Title
Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE

## ID
b6e04788-29e1-4557-bb14-77f761848ab8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-02-23

## Tags
attack.execution

## Description
Detects potentially suspicious file downloads from file sharing domains using PowerShell.exe

## References
https://labs.withsecure.com/publications/fin7-target-veeam-servers
https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".DownloadString(" OR TgtProcCmdLine containsCIS ".DownloadFile(" OR TgtProcCmdLine containsCIS "Invoke-WebRequest " OR TgtProcCmdLine containsCIS "iwr " OR TgtProcCmdLine containsCIS "wget ") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "anonfiles.com" OR TgtProcCmdLine containsCIS "cdn.discordapp.com" OR TgtProcCmdLine containsCIS "ddns.net" OR TgtProcCmdLine containsCIS "dl.dropboxusercontent.com" OR TgtProcCmdLine containsCIS "ghostbin.co" OR TgtProcCmdLine containsCIS "glitch.me" OR TgtProcCmdLine containsCIS "gofile.io" OR TgtProcCmdLine containsCIS "hastebin.com" OR TgtProcCmdLine containsCIS "mediafire.com" OR TgtProcCmdLine containsCIS "mega.nz" OR TgtProcCmdLine containsCIS "onrender.com" OR TgtProcCmdLine containsCIS "pages.dev" OR TgtProcCmdLine containsCIS "paste.ee" OR TgtProcCmdLine containsCIS "pastebin.com" OR TgtProcCmdLine containsCIS "pastebin.pl" OR TgtProcCmdLine containsCIS "pastetext.net" OR TgtProcCmdLine containsCIS "pixeldrain.com" OR TgtProcCmdLine containsCIS "privatlab.com" OR TgtProcCmdLine containsCIS "privatlab.net" OR TgtProcCmdLine containsCIS "send.exploit.in" OR TgtProcCmdLine containsCIS "sendspace.com" OR TgtProcCmdLine containsCIS "storage.googleapis.com" OR TgtProcCmdLine containsCIS "storjshare.io" OR TgtProcCmdLine containsCIS "supabase.co" OR TgtProcCmdLine containsCIS "temp.sh" OR TgtProcCmdLine containsCIS "transfer.sh" OR TgtProcCmdLine containsCIS "trycloudflare.com" OR TgtProcCmdLine containsCIS "ufile.io" OR TgtProcCmdLine containsCIS "w3spaces.com" OR TgtProcCmdLine containsCIS "workers.dev")))

```