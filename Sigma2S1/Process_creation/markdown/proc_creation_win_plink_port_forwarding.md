# proc_creation_win_plink_port_forwarding

## Title
Suspicious Plink Port Forwarding

## ID
48a61b29-389f-4032-b317-b30de6b95314

## Author
Florian Roth (Nextron Systems)

## Date
2021-01-19

## Tags
attack.command-and-control, attack.t1572, attack.lateral-movement, attack.t1021.001

## Description
Detects suspicious Plink tunnel port forwarding to a local port

## References
https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d

## False Positives
Administrative activity using a remote port forwarding to a local port

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -R " AND TgtProcDisplayName = "Command-line SSH, Telnet, and Rlogin client"))

```