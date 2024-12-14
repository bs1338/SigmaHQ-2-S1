# proc_creation_win_stordiag_susp_child_process

## Title
Execution via stordiag.exe

## ID
961e0abb-1b1e-4c84-a453-aafe56ad0d34

## Author
Austin Songer (@austinsonger)

## Date
2021-10-21

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe

## References
https://strontic.github.io/xcyclopedia/library/stordiag.exe-1F08FC87C373673944F6A7E8B18CD845.html
https://twitter.com/eral4m/status/1451112385041911809

## False Positives
Legitimate usage of stordiag.exe.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\schtasks.exe" OR TgtProcImagePath endswithCIS "\systeminfo.exe" OR TgtProcImagePath endswithCIS "\fltmc.exe") AND SrcProcImagePath endswithCIS "\stordiag.exe") AND (NOT (SrcProcImagePath startswithCIS "c:\windows\system32\" OR SrcProcImagePath startswithCIS "c:\windows\syswow64\"))))

```