# proc_creation_win_vscode_child_processes_anomalies

## Title
Potentially Suspicious Child Process Of VsCode

## ID
5a3164f2-b373-4152-93cf-090b13c12d27

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-26

## Tags
attack.execution, attack.defense-evasion, attack.t1218, attack.t1202

## Description
Detects uncommon or suspicious child processes spawning from a VsCode "code.exe" process. This could indicate an attempt of persistence via VsCode tasks or terminal profiles.

## References
https://twitter.com/nas_bench/status/1618021838407495681
https://twitter.com/nas_bench/status/1618021415852335105

## False Positives
In development environment where VsCode is used heavily. False positives may occur when developers use task to compile or execute different types of code. Remove or add processes accordingly

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\code.exe" AND (((TgtProcCmdLine containsCIS "Invoke-Expressions" OR TgtProcCmdLine containsCIS "IEX" OR TgtProcCmdLine containsCIS "Invoke-Command" OR TgtProcCmdLine containsCIS "ICM" OR TgtProcCmdLine containsCIS "DownloadString" OR TgtProcCmdLine containsCIS "rundll32" OR TgtProcCmdLine containsCIS "regsvr32" OR TgtProcCmdLine containsCIS "wscript" OR TgtProcCmdLine containsCIS "cscript") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe" OR TgtProcImagePath endswithCIS "\cmd.exe")) OR (TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcImagePath endswithCIS "\cscript.exe" OR TgtProcImagePath endswithCIS "\wscript.exe") OR (TgtProcImagePath containsCIS ":\Users\Public\" OR TgtProcImagePath containsCIS ":\Windows\Temp\" OR TgtProcImagePath containsCIS ":\Temp\"))))

```