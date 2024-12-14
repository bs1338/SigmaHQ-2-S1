# file_delete_win_delete_event_log_files

## Title
EventLog EVTX File Deleted

## ID
63c779ba-f638-40a0-a593-ddd45e8b1ddc

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1070

## Description
Detects the deletion of the event log files which may indicate an attempt to destroy forensic evidence

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND (TgtFilePath endswithCIS ".evtx" AND TgtFilePath startswithCIS "C:\Windows\System32\winevt\Logs\"))

```