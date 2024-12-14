# proc_creation_win_netsh_fw_rules_discovery

## Title
Firewall Configuration Discovery Via Netsh.EXE

## ID
0e4164da-94bc-450d-a7be-a4b176179f1f

## Author
frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'

## Date
2021-12-07

## Tags
attack.discovery, attack.t1016

## Description
Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-2---list-windows-firewall-rules
https://ss64.com/nt/netsh.html

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "config " OR TgtProcCmdLine containsCIS "state " OR TgtProcCmdLine containsCIS "rule " OR TgtProcCmdLine containsCIS "name=all") AND (TgtProcCmdLine containsCIS "netsh " AND TgtProcCmdLine containsCIS "show " AND TgtProcCmdLine containsCIS "firewall ")) AND TgtProcImagePath endswithCIS "\netsh.exe"))

```