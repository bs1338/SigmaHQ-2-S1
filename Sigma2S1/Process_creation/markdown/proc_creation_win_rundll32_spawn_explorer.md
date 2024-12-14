# proc_creation_win_rundll32_spawn_explorer

## Title
RunDLL32 Spawning Explorer

## ID
caa06de8-fdef-4c91-826a-7f9e163eef4b

## Author
elhoim, CD_ROM_

## Date
2022-04-27

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way

## References
https://redcanary.com/blog/intelligence-insights-november-2021/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\explorer.exe" AND SrcProcImagePath endswithCIS "\rundll32.exe") AND (NOT SrcProcCmdLine containsCIS "\shell32.dll,Control_RunDLL")))

```