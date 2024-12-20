# proc_creation_win_susp_network_sniffing

## Title
Potential Network Sniffing Activity Using Network Tools

## ID
ba1f7802-adc7-48b4-9ecb-81e227fddfd5

## Author
Timur Zinniatullin, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2019-10-21

## Tags
attack.credential-access, attack.discovery, attack.t1040

## Description
Detects potential network sniffing via use of network tools such as "tshark", "windump".
Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
 An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.


## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1040/T1040.md

## False Positives
Legitimate administration activity to troubleshoot network issues

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-i" AND TgtProcImagePath endswithCIS "\tshark.exe") OR TgtProcImagePath endswithCIS "\windump.exe"))

```