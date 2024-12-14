# proc_creation_win_office_outlook_execution_from_temp

## Title
Suspicious Execution From Outlook Temporary Folder

## ID
a018fdc3-46a3-44e5-9afb-2cd4af1d4b39

## Author
Florian Roth (Nextron Systems)

## Date
2019-10-01

## Tags
attack.initial-access, attack.t1566.001

## Description
Detects a suspicious program execution in Outlook temp folder

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath containsCIS "\Temporary Internet Files\Content.Outlook\")

```