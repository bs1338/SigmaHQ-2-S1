# file_delete_win_delete_powershell_command_history

## Title
PowerShell Console History Logs Deleted

## ID
ff301988-c231-4bd0-834c-ac9d73b86586

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-02-15

## Tags
attack.defense-evasion, attack.t1070

## Description
Detects the deletion of the PowerShell console History logs which may indicate an attempt to destroy forensic evidence

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "File Delete" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\PSReadLine\ConsoleHost_history.txt")

```