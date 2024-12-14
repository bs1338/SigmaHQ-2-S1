# file_event_win_susp_default_gpo_dir_write

## Title
Suspicious Files in Default GPO Folder

## ID
5f87308a-0a5b-4623-ae15-d8fa1809bc60

## Author
elhoim

## Date
2022-04-28

## Tags
attack.t1036.005, attack.defense-evasion

## Description
Detects the creation of copy of suspicious files (EXE/DLL) to the default GPO storage folder

## References
https://redcanary.com/blog/intelligence-insights-november-2021/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\" AND (TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe")))

```