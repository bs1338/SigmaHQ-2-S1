# proc_creation_win_schtasks_creation_temp_folder

## Title
Suspicious Scheduled Task Creation Involving Temp Folder

## ID
39019a4e-317f-4ce3-ae63-309a8c6b53c5

## Author
Florian Roth (Nextron Systems)

## Date
2021-03-11

## Tags
attack.execution, attack.persistence, attack.t1053.005

## Description
Detects the creation of scheduled tasks that involves a temporary folder and runs only once

## References
https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3

## False Positives
Administrative activity
Software installation

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /create " AND TgtProcCmdLine containsCIS " /sc once " AND TgtProcCmdLine containsCIS "\Temp\") AND TgtProcImagePath endswithCIS "\schtasks.exe"))

```