# proc_creation_win_winget_add_custom_source

## Title
Add New Download Source To Winget

## ID
05ebafc8-7aa2-4bcd-a269-2aec93f9e842

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-17

## Tags
attack.defense-evasion, attack.execution, attack.t1059

## Description
Detects usage of winget to add new additional download sources

## References
https://learn.microsoft.com/en-us/windows/package-manager/winget/source
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

## False Positives
False positive are expected with legitimate sources

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "source " AND TgtProcCmdLine containsCIS "add ") AND TgtProcImagePath endswithCIS "\winget.exe"))

```