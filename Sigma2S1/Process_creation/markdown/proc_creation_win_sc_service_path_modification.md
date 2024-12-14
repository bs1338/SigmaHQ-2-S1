# proc_creation_win_sc_service_path_modification

## Title
Suspicious Service Path Modification

## ID
138d3531-8793-4f50-a2cd-f291b2863d78

## Author
Victor Sergeev, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-21

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects service path modification via the "sc" binary to a suspicious command or path

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "powershell" OR TgtProcCmdLine containsCIS "cmd " OR TgtProcCmdLine containsCIS "mshta" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "cscript" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "svchost" OR TgtProcCmdLine containsCIS "dllhost" OR TgtProcCmdLine containsCIS "cmd.exe /c" OR TgtProcCmdLine containsCIS "cmd.exe /k" OR TgtProcCmdLine containsCIS "cmd.exe /r" OR TgtProcCmdLine containsCIS "cmd /c" OR TgtProcCmdLine containsCIS "cmd /k" OR TgtProcCmdLine containsCIS "cmd /r" OR TgtProcCmdLine containsCIS "C:\Users\Public" OR TgtProcCmdLine containsCIS "\Downloads\" OR TgtProcCmdLine containsCIS "\Desktop\" OR TgtProcCmdLine containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\" OR TgtProcCmdLine containsCIS "C:\Windows\TEMP\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp") AND (TgtProcCmdLine containsCIS "config" AND TgtProcCmdLine containsCIS "binPath") AND TgtProcImagePath endswithCIS "\sc.exe"))

```