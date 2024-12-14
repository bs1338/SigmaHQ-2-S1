# proc_creation_win_findstr_lsass

## Title
LSASS Process Reconnaissance Via Findstr.EXE

## ID
fe63010f-8823-4864-a96b-a7b4a0f7b929

## Author
Florian Roth (Nextron Systems)

## Date
2022-08-12

## Tags
attack.credential-access, attack.t1552.006

## Description
Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID

## References
https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "lsass" AND (TgtProcImagePath endswithCIS "\find.exe" OR TgtProcImagePath endswithCIS "\findstr.exe")) OR (TgtProcCmdLine containsCIS " -i \"lsass" OR TgtProcCmdLine containsCIS " /i \"lsass" OR TgtProcCmdLine containsCIS " â€“i \"lsass" OR TgtProcCmdLine containsCIS " â€”i \"lsass" OR TgtProcCmdLine containsCIS " â€•i \"lsass" OR TgtProcCmdLine containsCIS " -i lsass.exe" OR TgtProcCmdLine containsCIS " /i lsass.exe" OR TgtProcCmdLine containsCIS " â€“i lsass.exe" OR TgtProcCmdLine containsCIS " â€”i lsass.exe" OR TgtProcCmdLine containsCIS " â€•i lsass.exe" OR TgtProcCmdLine containsCIS "findstr \"lsass" OR TgtProcCmdLine containsCIS "findstr lsass" OR TgtProcCmdLine containsCIS "findstr.exe \"lsass" OR TgtProcCmdLine containsCIS "findstr.exe lsass")))

```