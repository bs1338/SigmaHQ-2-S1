# proc_creation_win_sc_new_kernel_driver

## Title
New Kernel Driver Via SC.EXE

## ID
431a1fdb-4799-4f3b-91c3-a683b003fc49

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-07-14

## Tags
attack.persistence, attack.privilege-escalation, attack.t1543.003

## Description
Detects creation of a new service (kernel driver) with the type "kernel"

## References
https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/

## False Positives
Rare legitimate installation of kernel drivers via sc.exe

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "create" OR TgtProcCmdLine containsCIS "config") AND (TgtProcCmdLine containsCIS "binPath" AND TgtProcCmdLine containsCIS "type" AND TgtProcCmdLine containsCIS "kernel") AND TgtProcImagePath endswithCIS "\sc.exe"))

```