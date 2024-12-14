# file_event_win_susp_startup_folder_persistence

## Title
Suspicious Startup Folder Persistence

## ID
28208707-fe31-437f-9a7f-4b1108b94d2e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-10

## Tags
attack.persistence, attack.t1547.001

## Description
Detects when a file with a suspicious extension is created in the startup folder

## References
https://github.com/last-byte/PersistenceSniper

## False Positives
Rare legitimate usage of some of the extensions mentioned in the rule

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath containsCIS "\Windows\Start Menu\Programs\Startup\" AND (TgtFilePath endswithCIS ".vbs" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".jar" OR TgtFilePath endswithCIS ".msi" OR TgtFilePath endswithCIS ".scr" OR TgtFilePath endswithCIS ".cmd")))

```