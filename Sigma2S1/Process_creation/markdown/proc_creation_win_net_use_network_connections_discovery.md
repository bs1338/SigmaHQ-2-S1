# proc_creation_win_net_use_network_connections_discovery

## Title
System Network Connections Discovery Via Net.EXE

## ID
1c67a717-32ba-409b-a45d-0fb704a73a81

## Author
frack113

## Date
2021-12-10

## Tags
attack.discovery, attack.t1049

## Description
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md#atomic-test-1---system-network-connections-discovery

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine endswithCIS " use" OR TgtProcCmdLine endswithCIS " sessions") OR (TgtProcCmdLine containsCIS " use " OR TgtProcCmdLine containsCIS " sessions ")) AND (TgtProcImagePath endswithCIS "\net.exe" OR TgtProcImagePath endswithCIS "\net1.exe")))

```