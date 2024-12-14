# proc_creation_win_qemu_suspicious_execution

## Title
Potentially Suspicious Usage Of Qemu

## ID
5fc297ae-25b6-488a-8f25-cc12ac29b744

## Author
Muhammad Faisal (@faisalusuf), Hunter Juhan (@threatHNTR)

## Date
2024-06-03

## Tags
attack.command-and-control, attack.t1090, attack.t1572

## Description
Detects potentially suspicious execution of the Qemu utility in a Windows environment.
Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky.


## References
https://securelist.com/network-tunneling-with-qemu/111803/
https://www.qemu.org/docs/master/system/invocation.html#hxtool-5

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-m 1M" OR TgtProcCmdLine containsCIS "-m 2M" OR TgtProcCmdLine containsCIS "-m 3M") AND (TgtProcCmdLine containsCIS "restrict=off" AND TgtProcCmdLine containsCIS "-netdev " AND TgtProcCmdLine containsCIS "connect=" AND TgtProcCmdLine containsCIS "-nographic")) AND (NOT (TgtProcCmdLine containsCIS " -cdrom " OR TgtProcCmdLine containsCIS " type=virt " OR TgtProcCmdLine containsCIS " -blockdev "))))

```