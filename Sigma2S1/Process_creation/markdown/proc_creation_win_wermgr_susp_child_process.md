# proc_creation_win_wermgr_susp_child_process

## Title
Suspicious Child Process Of Wermgr.EXE

## ID
396f6630-f3ac-44e3-bfc8-1b161bc00c4e

## Author
Florian Roth (Nextron Systems)

## Date
2022-10-14

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1055, attack.t1036

## Description
Detects suspicious Windows Error Reporting manager (wermgr.exe) child process

## References
https://www.trendmicro.com/en_us/research/22/j/black-basta-infiltrates-networks-via-qakbot-brute-ratel-and-coba.html
https://www.echotrail.io/insights/search/wermgr.exe
https://github.com/binderlabs/DirCreate2System

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\ipconfig.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe" OR TgtProcImagePath endswithCIS "\netstat.exe" OR TgtProcImagePath endswithCIS "\nslookup.exe" OR TgtProcImagePath endswithCIS "\powershell_ise.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\whoami.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") AND SrcProcImagePath endswithCIS "\wermgr.exe") AND (NOT ((TgtProcCmdLine containsCIS "-queuereporting" OR TgtProcCmdLine containsCIS "-responsepester") AND (TgtProcCmdLine containsCIS "C:\Windows\system32\WerConCpl.dll" AND TgtProcCmdLine containsCIS "LaunchErcApp ") AND TgtProcImagePath endswithCIS "\rundll32.exe"))))

```