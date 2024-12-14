# proc_creation_win_vmware_toolbox_cmd_persistence

## Title
Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script

## ID
7aa4e81a-a65c-4e10-9f81-b200eb229d7d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-06-14

## Tags
attack.execution, attack.persistence, attack.t1059

## Description
Detects execution of the "VMwareToolBoxCmd.exe" with the "script" and "set" flag to setup a specific script to run for a specific VM state

## References
https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
https://www.hexacorn.com/blog/2017/01/14/beyond-good-ol-run-key-part-53/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " script " AND TgtProcCmdLine containsCIS " set ") AND TgtProcImagePath endswithCIS "\VMwareToolBoxCmd.exe"))

```