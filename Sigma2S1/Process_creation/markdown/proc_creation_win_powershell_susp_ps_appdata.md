# proc_creation_win_powershell_susp_ps_appdata

## Title
PowerShell Script Run in AppData

## ID
ac175779-025a-4f12-98b0-acdaeb77ea85

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2019-01-09

## Tags
attack.execution, attack.t1059.001

## Description
Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder

## References
https://twitter.com/JohnLaTwC/status/1082851155481288706
https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03

## False Positives
Administrative scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "powershell.exe" OR TgtProcCmdLine containsCIS "\powershell" OR TgtProcCmdLine containsCIS "\pwsh" OR TgtProcCmdLine containsCIS "pwsh.exe") AND ((TgtProcCmdLine containsCIS "Local\" OR TgtProcCmdLine containsCIS "Roaming\") AND (TgtProcCmdLine containsCIS "/c " AND TgtProcCmdLine containsCIS "\AppData\"))))

```