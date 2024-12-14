# proc_creation_win_susp_parents

## Title
Suspicious Process Parents

## ID
cbec226f-63d9-4eca-9f52-dfb6652f24df

## Author
Florian Roth (Nextron Systems)

## Date
2022-03-21

## Tags
attack.defense-evasion, attack.t1036

## Description
Detects suspicious parent processes that should not have any children or should only have a single possible child program

## References
https://twitter.com/x86matthew/status/1505476263464607744?s=12
https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcImagePath endswithCIS "\minesweeper.exe" OR SrcProcImagePath endswithCIS "\winver.exe" OR SrcProcImagePath endswithCIS "\bitsadmin.exe") OR ((SrcProcImagePath endswithCIS "\csrss.exe" OR SrcProcImagePath endswithCIS "\certutil.exe" OR SrcProcImagePath endswithCIS "\eventvwr.exe" OR SrcProcImagePath endswithCIS "\calc.exe" OR SrcProcImagePath endswithCIS "\notepad.exe") AND (NOT (TgtProcImagePath IS NOT EMPTY OR (TgtProcImagePath endswithCIS "\WerFault.exe" OR TgtProcImagePath endswithCIS "\wermgr.exe" OR TgtProcImagePath endswithCIS "\conhost.exe" OR TgtProcImagePath endswithCIS "\mmc.exe" OR TgtProcImagePath endswithCIS "\win32calc.exe" OR TgtProcImagePath endswithCIS "\notepad.exe"))))))

```