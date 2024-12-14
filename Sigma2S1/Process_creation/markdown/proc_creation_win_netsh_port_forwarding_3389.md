# proc_creation_win_netsh_port_forwarding_3389

## Title
RDP Port Forwarding Rule Added Via Netsh.EXE

## ID
782d6f3e-4c5d-4b8c-92a3-1d05fed72e63

## Author
Florian Roth (Nextron Systems), oscd.community

## Date
2019-01-29

## Tags
attack.lateral-movement, attack.defense-evasion, attack.command-and-control, attack.t1090

## Description
Detects the execution of netsh to configure a port forwarding of port 3389 (RDP) rule

## References
https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html

## False Positives
Legitimate administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " i" AND TgtProcCmdLine containsCIS " p" AND TgtProcCmdLine containsCIS "=3389" AND TgtProcCmdLine containsCIS " c") AND TgtProcImagePath endswithCIS "\netsh.exe"))

```