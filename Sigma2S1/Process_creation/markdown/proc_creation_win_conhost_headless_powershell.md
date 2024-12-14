# proc_creation_win_conhost_headless_powershell

## Title
Powershell Executed From Headless ConHost Process

## ID
056c7317-9a09-4bd4-9067-d051312752ea

## Author
Matt Anderson (Huntress)

## Date
2024-07-23

## Tags
attack.defense-evasion, attack.t1059.001, attack.t1059.003

## Description
Detects the use of powershell commands from headless ConHost window.
 The "--headless" flag hides the windows from the user upon execution.


## References
https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "--headless" AND TgtProcCmdLine containsCIS "powershell") AND TgtProcImagePath endswithCIS "\conhost.exe"))

```