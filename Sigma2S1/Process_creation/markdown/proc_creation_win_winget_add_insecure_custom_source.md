# proc_creation_win_winget_add_insecure_custom_source

## Title
Add Insecure Download Source To Winget

## ID
81a0ecb5-0a41-4ba1-b2ba-c944eb92bfa2

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-17

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects usage of winget to add a new insecure (http) download source.
 Winget will not allow the addition of insecure sources, hence this could indicate potential suspicious activity (or typos)


## References
https://learn.microsoft.com/en-us/windows/package-manager/winget/source
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

## False Positives
False positives might occur if the users are unaware of such control checks

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "source " AND TgtProcCmdLine containsCIS "add " AND TgtProcCmdLine containsCIS "http://") AND TgtProcImagePath endswithCIS "\winget.exe"))

```