# proc_creation_win_susp_network_command

## Title
Suspicious Network Command

## ID
a29c1813-ab1f-4dde-b489-330b952e91ae

## Author
frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'

## Date
2021-12-07

## Tags
attack.discovery, attack.t1016

## Description
Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows

## False Positives
Administrator, hotline ask to user

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "ipconfig /all" OR TgtProcCmdLine containsCIS "netsh interface show interface" OR TgtProcCmdLine containsCIS "arp -a" OR TgtProcCmdLine containsCIS "nbtstat -n" OR TgtProcCmdLine containsCIS "net config" OR TgtProcCmdLine containsCIS "route print"))

```