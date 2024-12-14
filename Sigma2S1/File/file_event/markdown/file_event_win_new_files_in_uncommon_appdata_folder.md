# file_event_win_new_files_in_uncommon_appdata_folder

## Title
Suspicious File Creation In Uncommon AppData Folder

## ID
d7b50671-d1ad-4871-aa60-5aa5b331fe04

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-05

## Tags
attack.defense-evasion, attack.execution

## Description
Detects the creation of suspicious files and folders inside the user's AppData folder but not inside any of the common and well known directories (Local, Romaing, LocalLow). This method could be used as a method to bypass detection who exclude the AppData folder in fear of FPs

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\AppData\" AND (TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".cmd" OR TgtFilePath endswithCIS ".cpl" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".iso" OR TgtFilePath endswithCIS ".lnk" OR TgtFilePath endswithCIS ".msi" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".psm1" OR TgtFilePath endswithCIS ".scr" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs") AND TgtFilePath startswithCIS "C:\Users\") AND (NOT ((TgtFilePath containsCIS "\AppData\Local\" OR TgtFilePath containsCIS "\AppData\LocalLow\" OR TgtFilePath containsCIS "\AppData\Roaming\") AND TgtFilePath startswithCIS "C:\Users\"))))

```