# proc_creation_win_vmware_toolbox_cmd_persistence_susp

## Title
Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script

## ID
236d8e89-ed95-4789-a982-36f4643738ba

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-14

## Tags
attack.execution, attack.persistence, attack.t1059

## Description
Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script that's located in a potentially suspicious location to run for a specific VM state

## References
https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " script " AND TgtProcCmdLine containsCIS " set ") AND TgtProcImagePath endswithCIS "\VMwareToolBoxCmd.exe" AND (TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp")))

```