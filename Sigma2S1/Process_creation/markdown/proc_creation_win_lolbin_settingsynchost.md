# proc_creation_win_lolbin_settingsynchost

## Title
Using SettingSyncHost.exe as LOLBin

## ID
b2ddd389-f676-4ac4-845a-e00781a48e5f

## Author
Anton Kutepov, oscd.community

## Date
2020-02-05

## Tags
attack.execution, attack.defense-evasion, attack.t1574.008

## Description
Detects using SettingSyncHost.exe to run hijacked binary

## References
https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((NOT (TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\")) AND (SrcProcCmdLine containsCIS "cmd.exe /c" AND SrcProcCmdLine containsCIS "RoamDiag.cmd" AND SrcProcCmdLine containsCIS "-outputpath")))

```