# proc_creation_win_susp_ntds

## Title
Suspicious Process Patterns NTDS.DIT Exfil

## ID
8bc64091-6875-4881-aaf9-7bd25b5dda08

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-11

## Tags
attack.credential-access, attack.t1003.003

## Description
Detects suspicious process patterns used in NTDS.DIT exfiltration

## References
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
https://www.n00py.io/2022/03/manipulating-user-passwords-without-mimikatz/
https://pentestlab.blog/tag/ntds-dit/
https://github.com/samratashok/nishang/blob/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Copy-VSS.ps1
https://github.com/zcgonvh/NTDSDumpEx
https://github.com/rapid7/metasploit-framework/blob/d297adcebb5c1df6fe30b12ca79b161deb71571c/data/post/powershell/NTDSgrab.ps1
https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "ac i ntds" AND TgtProcCmdLine containsCIS "create full") OR (TgtProcCmdLine containsCIS "/c copy " AND TgtProcCmdLine containsCIS "\windows\ntds\ntds.dit") OR (TgtProcCmdLine containsCIS "activate instance ntds" AND TgtProcCmdLine containsCIS "create full") OR (TgtProcCmdLine containsCIS "powershell" AND TgtProcCmdLine containsCIS "ntds.dit") OR ((TgtProcImagePath endswithCIS "\NTDSDump.exe" OR TgtProcImagePath endswithCIS "\NTDSDumpEx.exe") OR (TgtProcCmdLine containsCIS "ntds.dit" AND TgtProcCmdLine containsCIS "system.hiv") OR TgtProcCmdLine containsCIS "NTDSgrab.ps1")) OR (((SrcProcImagePath containsCIS "\apache" OR SrcProcImagePath containsCIS "\tomcat" OR SrcProcImagePath containsCIS "\AppData\" OR SrcProcImagePath containsCIS "\Temp\" OR SrcProcImagePath containsCIS "\Public\" OR SrcProcImagePath containsCIS "\PerfLogs\") OR (TgtProcImagePath containsCIS "\apache" OR TgtProcImagePath containsCIS "\tomcat" OR TgtProcImagePath containsCIS "\AppData\" OR TgtProcImagePath containsCIS "\Temp\" OR TgtProcImagePath containsCIS "\Public\" OR TgtProcImagePath containsCIS "\PerfLogs\")) AND TgtProcCmdLine containsCIS "ntds.dit")))

```