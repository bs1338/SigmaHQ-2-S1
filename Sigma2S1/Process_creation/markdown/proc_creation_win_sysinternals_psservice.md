# proc_creation_win_sysinternals_psservice

## Title
Sysinternals PsService Execution

## ID
3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-16

## Tags
attack.discovery, attack.persistence, attack.t1543.003

## Description
Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering

## References
https://learn.microsoft.com/en-us/sysinternals/downloads/psservice

## False Positives
Legitimate use of PsService by an administrator

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\PsService.exe" OR TgtProcImagePath endswithCIS "\PsService64.exe"))

```