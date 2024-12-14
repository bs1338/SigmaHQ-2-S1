# proc_creation_win_hktl_winpeas

## Title
HackTool - winPEAS Execution

## ID
98b53e78-ebaf-46f8-be06-421aafd176d9

## Author
Georg Lauenstein (sure[secure])

## Date
2022-09-19

## Tags
attack.privilege-escalation, attack.t1082, attack.t1087, attack.t1046

## Description
WinPEAS is a script that search for possible paths to escalate privileges on Windows hosts. The checks are explained on book.hacktricks.xyz

## References
https://github.com/carlospolop/PEASS-ng
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "https://github.com/carlospolop/PEASS-ng/releases/latest/download/" OR (TgtProcCmdLine containsCIS " applicationsinfo" OR TgtProcCmdLine containsCIS " browserinfo" OR TgtProcCmdLine containsCIS " eventsinfo" OR TgtProcCmdLine containsCIS " fileanalysis" OR TgtProcCmdLine containsCIS " filesinfo" OR TgtProcCmdLine containsCIS " processinfo" OR TgtProcCmdLine containsCIS " servicesinfo" OR TgtProcCmdLine containsCIS " windowscreds") OR (SrcProcCmdLine endswithCIS " -linpeas" OR TgtProcCmdLine endswithCIS " -linpeas") OR (TgtProcImagePath endswithCIS "\winPEASany_ofs.exe" OR TgtProcImagePath endswithCIS "\winPEASany.exe" OR TgtProcImagePath endswithCIS "\winPEASx64_ofs.exe" OR TgtProcImagePath endswithCIS "\winPEASx64.exe" OR TgtProcImagePath endswithCIS "\winPEASx86_ofs.exe" OR TgtProcImagePath endswithCIS "\winPEASx86.exe")))

```