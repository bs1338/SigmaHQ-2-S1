# proc_creation_win_netsh_fw_allow_rdp

## Title
RDP Connection Allowed Via Netsh.EXE

## ID
01aeb693-138d-49d2-9403-c4f52d7d3d62

## Author
Sander Wiebing

## Date
2020-05-23

## Tags
attack.defense-evasion, attack.t1562.004

## Description
Detects usage of the netsh command to open and allow connections to port 3389 (RDP). As seen used by Sarwent Malware

## References
https://labs.sentinelone.com/sarwent-malware-updates-command-detonation/

## False Positives
Legitimate administration activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "portopening" OR TgtProcCmdLine containsCIS "allow") AND (TgtProcCmdLine containsCIS "firewall " AND TgtProcCmdLine containsCIS "add " AND TgtProcCmdLine containsCIS "tcp " AND TgtProcCmdLine containsCIS "3389")) AND TgtProcImagePath endswithCIS "\netsh.exe"))

```