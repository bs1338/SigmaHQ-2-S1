# proc_creation_win_susp_workfolders

## Title
Execution via WorkFolders.exe

## ID
0bbc6369-43e3-453d-9944-cae58821c173

## Author
Maxime Thiebaut (@0xThiebaut)

## Date
2021-10-21

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects using WorkFolders.exe to execute an arbitrary control.exe

## References
https://twitter.com/elliotkillick/status/1449812843772227588

## False Positives
Legitimate usage of the uncommon Windows Work Folders feature.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\control.exe" AND SrcProcImagePath endswithCIS "\WorkFolders.exe") AND (NOT TgtProcImagePath = "C:\Windows\System32\control.exe")))

```