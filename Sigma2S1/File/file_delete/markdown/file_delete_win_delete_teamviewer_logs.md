# file_delete_win_delete_teamviewer_logs

## Title
TeamViewer Log File Deleted

## ID
b1decb61-ed83-4339-8e95-53ea51901720

## Author
frack113

## Date
2022-01-16

## Tags
attack.defense-evasion, attack.t1070.004

## Description
Detects the deletion of the TeamViewer log files which may indicate an attempt to destroy forensic evidence

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.004/T1070.004.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND ((TgtFilePath containsCIS "\TeamViewer_" AND TgtFilePath endswithCIS ".log") AND (NOT SrcProcImagePath = "C:\Windows\system32\svchost.exe")))

```