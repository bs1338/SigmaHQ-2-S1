# proc_creation_win_hktl_winpwn

## Title
HackTool - WinPwn Execution

## ID
d557dc06-62e8-4468-a8e8-7984124908ce

## Author
Swachchhanda Shrawan Poudel

## Date
2023-12-04

## Tags
attack.credential-access, attack.defense-evasion, attack.discovery, attack.execution, attack.privilege-escalation, attack.t1046, attack.t1082, attack.t1106, attack.t1518, attack.t1548.002, attack.t1552.001, attack.t1555, attack.t1555.003

## Description
Detects commandline keywords indicative of potential usge of the tool WinPwn. A tool for Windows and Active Directory reconnaissance and exploitation.


## References
https://github.com/S3cur3Th1sSh1t/WinPwn
https://www.publicnow.com/view/EB87DB49C654D9B63995FAD4C9DE3D3CC4F6C3ED?1671634841
https://reconshell.com/winpwn-tool-for-internal-windows-pentesting-and-ad-security/
https://github.com/redcanaryco/atomic-red-team/blob/4d6c4e8e23d465af7a2388620cfe3f8c76e16cf0/atomics/T1082/T1082.md
https://grep.app/search?q=winpwn&filter[repo][0]=redcanaryco/atomic-red-team

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Offline_Winpwn" OR TgtProcCmdLine containsCIS "WinPwn " OR TgtProcCmdLine containsCIS "WinPwn.exe" OR TgtProcCmdLine containsCIS "WinPwn.ps1"))

```