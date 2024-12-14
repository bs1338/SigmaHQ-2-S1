# file_event_win_hktl_crackmapexec_indicators

## Title
HackTool - CrackMapExec File Indicators

## ID
736ffa74-5f6f-44ca-94ef-1c0df4f51d2a

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-03-11

## Tags
attack.credential-access, attack.t1003.001

## Description
Detects file creation events with filename patterns used by CrackMapExec.

## References
https://github.com/byt3bl33d3r/CrackMapExec/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND (TgtFilePath startswithCIS "C:\Windows\Temp\" AND ((TgtFilePath RegExp "\\\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.txt$" OR TgtFilePath RegExp "\\\\[a-zA-Z]{8}\\.tmp$") OR (TgtFilePath endswithCIS "\temp.ps1" OR TgtFilePath endswithCIS "\msol.ps1"))))

```