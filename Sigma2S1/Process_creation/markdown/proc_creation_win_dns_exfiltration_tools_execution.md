# proc_creation_win_dns_exfiltration_tools_execution

## Title
DNS Exfiltration and Tunneling Tools Execution

## ID
98a96a5a-64a0-4c42-92c5-489da3866cb0

## Author
Daniil Yugoslavskiy, oscd.community

## Date
2019-10-24

## Tags
attack.exfiltration, attack.t1048.001, attack.command-and-control, attack.t1071.004, attack.t1132.001

## Description
Well-known DNS Exfiltration tools execution

## References
https://github.com/iagox86/dnscat2
https://github.com/yarrick/iodine

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\iodine.exe" OR TgtProcImagePath containsCIS "\dnscat2"))

```