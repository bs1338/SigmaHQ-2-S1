# file_event_win_remcom_service

## Title
RemCom Service File Creation

## ID
7eff1a7f-dd45-4c20-877a-f21e342a7611

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-04

## Tags
attack.execution, attack.t1569.002, attack.s0029

## Description
Detects default RemCom service filename which indicates RemCom service installation and execution

## References
https://github.com/kavika13/RemCom/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "File" AND (EndpointOS = "windows" AND TgtFilePath endswithCIS "\RemComSvc.exe")

```