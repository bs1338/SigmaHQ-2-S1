# proc_creation_win_susp_shadow_copies_deletion

## Title
Shadow Copies Deletion Using Operating Systems Utilities

## ID
c947b146-0abc-4c87-9c64-b17e9d7274a2

## Author
Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)

## Date
2019-10-22

## Tags
attack.defense-evasion, attack.impact, attack.t1070, attack.t1490

## Description
Shadow Copies deletion using operating systems utilities

## References
https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
https://blog.talosintelligence.com/2017/05/wannacry.html
https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
https://www.bleepingcomputer.com/news/security/why-everyone-should-disable-vssadmin-exe-now/
https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
https://github.com/Neo23x0/Raccine#the-process
https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/gen_ransomware_command_lines.yar
https://redcanary.com/blog/intelligence-insights-october-2021/
https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/blackbyte-exbyte-ransomware

## False Positives
Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
LANDesk LDClient Ivanti-PSModule (PS EncodedCommand)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "shadow" AND TgtProcCmdLine containsCIS "delete") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\wmic.exe" OR TgtProcImagePath endswithCIS "\vssadmin.exe" OR TgtProcImagePath endswithCIS "\diskshadow.exe")) OR ((TgtProcCmdLine containsCIS "delete" AND TgtProcCmdLine containsCIS "catalog" AND TgtProcCmdLine containsCIS "quiet") AND TgtProcImagePath endswithCIS "\wbadmin.exe") OR (((TgtProcCmdLine containsCIS "unbounded" OR TgtProcCmdLine containsCIS "/MaxSize=") AND (TgtProcCmdLine containsCIS "resize" AND TgtProcCmdLine containsCIS "shadowstorage")) AND TgtProcImagePath endswithCIS "\vssadmin.exe")))

```