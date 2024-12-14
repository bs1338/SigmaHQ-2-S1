# proc_creation_win_susp_eventlog_content_recon

## Title
Potentially Suspicious EventLog Recon Activity Using Log Query Utilities

## ID
beaa66d6-aa1b-4e3c-80f5-e0145369bfaf

## Author
Nasreddine Bencherchali (Nextron Systems), X__Junior (Nextron Systems)

## Date
2022-09-09

## Tags
attack.credential-access, attack.discovery, attack.t1552

## Description
Detects execution of different log query utilities and commands to search and dump the content of specific event logs or look for specific event IDs.
This technique is used by threat actors in order to extract sensitive information from events logs such as usernames, IP addresses, hostnames, etc.


## References
http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise/
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
https://www.group-ib.com/blog/apt41-world-tour-2021/
https://labs.withsecure.com/content/dam/labs/docs/f-secureLABS-tlp-white-lazarus-threat-intel-report2.pdf
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
http://www.solomonson.com/posts/2010-07-09-reading-eventviewer-command-line/
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

## False Positives
Legitimate usage of the utility by administrators to query the event log

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine = "*-InstanceId 462**" OR TgtProcCmdLine = "*.eventid -eq 462**" OR TgtProcCmdLine = "*EventCode=*462**" OR TgtProcCmdLine = "*EventIdentifier=*462**" OR TgtProcCmdLine = "*System[EventID=462*]*" OR TgtProcCmdLine containsCIS "-InstanceId 4778" OR TgtProcCmdLine containsCIS ".eventid -eq 4778" OR TgtProcCmdLine containsCIS "System[EventID=4778]" OR TgtProcCmdLine = "*EventCode=*4778**" OR TgtProcCmdLine = "*EventIdentifier=*4778**" OR TgtProcCmdLine containsCIS "-InstanceId 25" OR TgtProcCmdLine containsCIS ".eventid -eq 25" OR TgtProcCmdLine containsCIS "System[EventID=25]" OR TgtProcCmdLine = "*EventCode=*25**" OR TgtProcCmdLine = "*EventIdentifier=*25**") OR (TgtProcCmdLine containsCIS "Microsoft-Windows-PowerShell" OR TgtProcCmdLine containsCIS "Microsoft-Windows-Security-Auditing" OR TgtProcCmdLine containsCIS "Microsoft-Windows-TerminalServices-LocalSessionManager" OR TgtProcCmdLine containsCIS "Microsoft-Windows-TerminalServices-RemoteConnectionManager" OR TgtProcCmdLine containsCIS "Microsoft-Windows-Windows Defender" OR TgtProcCmdLine containsCIS "PowerShellCore" OR TgtProcCmdLine containsCIS "Security" OR TgtProcCmdLine containsCIS "Windows PowerShell")) AND ((TgtProcCmdLine containsCIS "Select" AND TgtProcCmdLine containsCIS "Win32_NTLogEvent") OR ((TgtProcCmdLine containsCIS " qe " OR TgtProcCmdLine containsCIS " query-events ") AND TgtProcImagePath endswithCIS "\wevtutil.exe") OR (TgtProcCmdLine containsCIS " ntevent" AND TgtProcImagePath endswithCIS "\wmic.exe") OR (TgtProcCmdLine containsCIS "Get-WinEvent " OR TgtProcCmdLine containsCIS "get-eventlog "))))

```