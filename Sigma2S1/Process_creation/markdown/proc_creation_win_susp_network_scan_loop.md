# proc_creation_win_susp_network_scan_loop

## Title
Suspicious Scan Loop Network

## ID
f8ad2e2c-40b6-4117-84d7-20b89896ab23

## Author
frack113

## Date
2022-03-12

## Tags
attack.execution, attack.t1059, attack.discovery, attack.t1018

## Description
Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
https://ss64.com/nt/for.html
https://ss64.com/ps/foreach-object.html

## False Positives
Legitimate script

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "for " OR TgtProcCmdLine containsCIS "foreach ") AND (TgtProcCmdLine containsCIS "nslookup" OR TgtProcCmdLine containsCIS "ping")))

```