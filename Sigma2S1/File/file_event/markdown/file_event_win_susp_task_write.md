# file_event_win_susp_task_write

## Title
Suspicious Scheduled Task Write to System32 Tasks

## ID
80e1f67a-4596-4351-98f5-a9c3efabac95

## Author
Florian Roth (Nextron Systems)

## Date
2021-11-16

## Tags
attack.persistence, attack.execution, attack.t1053

## Description
Detects the creation of tasks from processes executed from suspicious locations

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND ((SrcProcImagePath containsCIS "\AppData\" OR SrcProcImagePath containsCIS "C:\PerfLogs" OR SrcProcImagePath containsCIS "\Windows\System32\config\systemprofile") AND TgtFilePath containsCIS "\Windows\System32\Tasks"))

```