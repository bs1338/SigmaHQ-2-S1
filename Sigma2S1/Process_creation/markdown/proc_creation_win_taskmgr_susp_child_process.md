# proc_creation_win_taskmgr_susp_child_process

## Title
New Process Created Via Taskmgr.EXE

## ID
3d7679bd-0c00-440c-97b0-3f204273e6c7

## Author
Florian Roth (Nextron Systems)

## Date
2018-03-13

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC

## References
https://twitter.com/ReneFreingruber/status/1172244989335810049

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (SrcProcImagePath endswithCIS "\taskmgr.exe" AND (NOT (TgtProcImagePath endswithCIS ":\Windows\System32\mmc.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\resmon.exe" OR TgtProcImagePath endswithCIS ":\Windows\System32\Taskmgr.exe"))))

```