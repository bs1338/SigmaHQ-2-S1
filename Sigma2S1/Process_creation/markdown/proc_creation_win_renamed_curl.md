# proc_creation_win_renamed_curl

## Title
Renamed CURL.EXE Execution

## ID
7530cd3d-7671-43e3-b209-976966f6ea48

## Author
X__Junior (Nextron Systems)

## Date
2023-09-11

## Tags
attack.execution, attack.t1059, attack.defense-evasion, attack.t1202

## Description
Detects the execution of a renamed "CURL.exe" binary based on the PE metadata fields

## References
https://twitter.com/Kostastsale/status/1700965142828290260

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcDisplayName = "The curl executable" AND (NOT TgtProcImagePath containsCIS "\curl")))

```