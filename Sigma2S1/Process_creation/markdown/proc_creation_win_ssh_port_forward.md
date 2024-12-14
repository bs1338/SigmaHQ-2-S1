# proc_creation_win_ssh_port_forward

## Title
Port Forwarding Activity Via SSH.EXE

## ID
327f48c1-a6db-4eb8-875a-f6981f1b0183

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-12

## Tags
attack.command-and-control, attack.lateral-movement, attack.t1572, attack.t1021.001, attack.t1021.004

## Description
Detects port forwarding activity via SSH.exe

## References
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Administrative activity using a remote port forwarding to a local port

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -R " OR TgtProcCmdLine containsCIS " /R " OR TgtProcCmdLine containsCIS " â€“R " OR TgtProcCmdLine containsCIS " â€”R " OR TgtProcCmdLine containsCIS " â€•R ") AND TgtProcImagePath endswithCIS "\ssh.exe"))

```