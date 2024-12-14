# proc_creation_win_wmic_recon_computersystem

## Title
Computer System Reconnaissance Via Wmic.EXE

## ID
9d7ca793-f6bd-471c-8d0f-11e68b2f0d2f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-09-08

## Tags
attack.discovery, attack.execution, attack.t1047

## Description
Detects execution of wmic utility with the "computersystem" flag in order to obtain information about the machine such as the domain, username, model, etc.

## References
https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "computersystem" AND TgtProcImagePath endswithCIS "\wmic.exe"))

```