# proc_creation_win_provlaunch_potential_abuse

## Title
Potential Provlaunch.EXE Binary Proxy Execution Abuse

## ID
7f5d1c9a-3e83-48df-95a7-2b98aae6c13c

## Author
Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel

## Date
2023-08-08

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects child processes of "provlaunch.exe" which might indicate potential abuse to proxy execution.

## References
https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
https://twitter.com/0gtweet/status/1674399582162153472

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\provlaunch.exe" AND (NOT ((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\mshta.exe" OR TgtProcImagePath endswithCIS "\notepad.exe" OR TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS ":\PerfLogs\" OR TgtProcImagePath containsCIS ":\Temp\" OR TgtProcImagePath containsCIS ":\Users\Public\" OR TgtProcImagePath containsCIS "\AppData\Temp\" OR TgtProcImagePath containsCIS "\Windows\System32\Tasks\" OR TgtProcImagePath containsCIS "\Windows\Tasks\" OR TgtProcImagePath containsCIS "\Windows\Temp\")))))

```