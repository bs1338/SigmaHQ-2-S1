# file_event_win_perflogs_susp_files

## Title
Suspicious File Created In PerfLogs

## ID
bbb7e38c-0b41-4a11-b306-d2a457b7ac2b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-05

## Tags
attack.execution, attack.t1059

## Description
Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files

## References
Internal Research
https://labs.withsecure.com/publications/fin7-target-veeam-servers

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((TgtFilePath endswithCIS ".7z" OR TgtFilePath endswithCIS ".bat" OR TgtFilePath endswithCIS ".bin" OR TgtFilePath endswithCIS ".chm" OR TgtFilePath endswithCIS ".dll" OR TgtFilePath endswithCIS ".exe" OR TgtFilePath endswithCIS ".hta" OR TgtFilePath endswithCIS ".lnk" OR TgtFilePath endswithCIS ".ps1" OR TgtFilePath endswithCIS ".psm1" OR TgtFilePath endswithCIS ".py" OR TgtFilePath endswithCIS ".scr" OR TgtFilePath endswithCIS ".sys" OR TgtFilePath endswithCIS ".vbe" OR TgtFilePath endswithCIS ".vbs" OR TgtFilePath endswithCIS ".zip") AND TgtFilePath startswithCIS "C:\PerfLogs\"))

```