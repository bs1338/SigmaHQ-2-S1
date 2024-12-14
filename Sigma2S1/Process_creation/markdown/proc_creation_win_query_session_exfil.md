# proc_creation_win_query_session_exfil

## Title
Query Usage To Exfil Data

## ID
53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-01

## Tags
attack.execution

## Description
Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use

## References
https://twitter.com/MichalKoczwara/status/1553634816016498688

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "session >" OR TgtProcCmdLine containsCIS "process >") AND TgtProcImagePath endswithCIS ":\Windows\System32\query.exe"))

```