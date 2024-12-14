# proc_creation_win_netsh_port_forwarding

## Title
New Port Forwarding Rule Added Via Netsh.EXE

## ID
322ed9ec-fcab-4f67-9a34-e7c6aef43614

## Author
Florian Roth (Nextron Systems), omkar72, oscd.community, Swachchhanda Shrawan Poudel

## Date
2019-01-29

## Tags
attack.lateral-movement, attack.defense-evasion, attack.command-and-control, attack.t1090

## Description
Detects the execution of netsh commands that configure a new port forwarding (PortProxy) rule

## References
https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
https://adepts.of0x.cc/netsh-portproxy-code/
https://www.dfirnotes.net/portproxy_detection/

## False Positives
Legitimate administration activity
WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\netsh.exe" AND ((TgtProcCmdLine containsCIS "interface" AND TgtProcCmdLine containsCIS "portproxy" AND TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "v4tov4") OR (TgtProcCmdLine containsCIS "i " AND TgtProcCmdLine containsCIS "p " AND TgtProcCmdLine containsCIS "a " AND TgtProcCmdLine containsCIS "v ") OR (TgtProcCmdLine containsCIS "connectp" AND TgtProcCmdLine containsCIS "listena" AND TgtProcCmdLine containsCIS "c="))))

```