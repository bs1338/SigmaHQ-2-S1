# proc_creation_win_powershell_base64_wmi_classes

## Title
PowerShell Base64 Encoded WMI Classes

## ID
1816994b-42e1-4fb1-afd2-134d88184f71

## Author
Christian Burkard (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-30

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1027

## Description
Detects calls to base64 encoded WMI class such as "Win32_ShadowCopy", "Win32_ScheduledJob", etc.

## References
https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/mal_revil.yar

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND ((TgtProcCmdLine containsCIS "VwBpAG4AMwAyAF8ATABvAGcAZwBlAGQATwBuAFUAcwBlAHIA" OR TgtProcCmdLine containsCIS "cAaQBuADMAMgBfAEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByA" OR TgtProcCmdLine containsCIS "XAGkAbgAzADIAXwBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcg" OR TgtProcCmdLine containsCIS "V2luMzJfTG9nZ2VkT25Vc2Vy" OR TgtProcCmdLine containsCIS "dpbjMyX0xvZ2dlZE9uVXNlc" OR TgtProcCmdLine containsCIS "XaW4zMl9Mb2dnZWRPblVzZX") OR (TgtProcCmdLine containsCIS "VwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcw" OR TgtProcCmdLine containsCIS "cAaQBuADMAMgBfAFAAcgBvAGMAZQBzAHMA" OR TgtProcCmdLine containsCIS "XAGkAbgAzADIAXwBQAHIAbwBjAGUAcwBzA" OR TgtProcCmdLine containsCIS "V2luMzJfUHJvY2Vzc" OR TgtProcCmdLine containsCIS "dpbjMyX1Byb2Nlc3" OR TgtProcCmdLine containsCIS "XaW4zMl9Qcm9jZXNz") OR (TgtProcCmdLine containsCIS "VwBpAG4AMwAyAF8AUwBjAGgAZQBkAHUAbABlAGQASgBvAGIA" OR TgtProcCmdLine containsCIS "cAaQBuADMAMgBfAFMAYwBoAGUAZAB1AGwAZQBkAEoAbwBiA" OR TgtProcCmdLine containsCIS "XAGkAbgAzADIAXwBTAGMAaABlAGQAdQBsAGUAZABKAG8AYg" OR TgtProcCmdLine containsCIS "V2luMzJfU2NoZWR1bGVkSm9i" OR TgtProcCmdLine containsCIS "dpbjMyX1NjaGVkdWxlZEpvY" OR TgtProcCmdLine containsCIS "XaW4zMl9TY2hlZHVsZWRKb2") OR (TgtProcCmdLine containsCIS "VwBpAG4AMwAyAF8AUwBoAGEAZABvAHcAYwBvAHAAeQ" OR TgtProcCmdLine containsCIS "cAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkA" OR TgtProcCmdLine containsCIS "XAGkAbgAzADIAXwBTAGgAYQBkAG8AdwBjAG8AcAB5A" OR TgtProcCmdLine containsCIS "V2luMzJfU2hhZG93Y29we" OR TgtProcCmdLine containsCIS "dpbjMyX1NoYWRvd2NvcH" OR TgtProcCmdLine containsCIS "XaW4zMl9TaGFkb3djb3B5") OR (TgtProcCmdLine containsCIS "VwBpAG4AMwAyAF8AVQBzAGUAcgBBAGMAYwBvAHUAbgB0A" OR TgtProcCmdLine containsCIS "cAaQBuADMAMgBfAFUAcwBlAHIAQQBjAGMAbwB1AG4AdA" OR TgtProcCmdLine containsCIS "XAGkAbgAzADIAXwBVAHMAZQByAEEAYwBjAG8AdQBuAHQA" OR TgtProcCmdLine containsCIS "V2luMzJfVXNlckFjY291bn" OR TgtProcCmdLine containsCIS "dpbjMyX1VzZXJBY2NvdW50" OR TgtProcCmdLine containsCIS "XaW4zMl9Vc2VyQWNjb3Vud"))))

```