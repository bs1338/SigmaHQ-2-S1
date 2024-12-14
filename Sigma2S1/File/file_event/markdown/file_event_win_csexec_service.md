# file_event_win_csexec_service

## Title
CSExec Service File Creation

## ID
f0e2b768-5220-47dd-b891-d57b96fc0ec1

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-04

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects default CSExec service filename which indicates CSExec service installation and execution

## References
https://github.com/malcomvetter/CSExec

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\csexecsvc.exe")

```