# proc_creation_win_winget_add_susp_custom_source

## Title
Add Potential Suspicious New Download Source To Winget

## ID
c15a46a0-07d4-4c87-b4b6-89207835a83b

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-17

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects usage of winget to add new potentially suspicious download sources

## References
https://learn.microsoft.com/en-us/windows/package-manager/winget/source
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "source " AND TgtProcCmdLine containsCIS "add ") AND TgtProcImagePath endswithCIS "\winget.exe" AND TgtProcCmdLine RegExp "://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"))

```