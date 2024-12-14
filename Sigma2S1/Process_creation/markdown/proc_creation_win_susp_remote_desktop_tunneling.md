# proc_creation_win_susp_remote_desktop_tunneling

## Title
Potential Remote Desktop Tunneling

## ID
8a3038e8-9c9d-46f8-b184-66234a160f6f

## Author
Tim Rauch, Elastic (idea)

## Date
2022-09-27

## Tags
attack.lateral-movement, attack.t1021

## Description
Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.

## References
https://www.elastic.co/guide/en/security/current/potential-remote-desktop-tunneling-detected.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ":3389" AND (TgtProcCmdLine containsCIS " -L " OR TgtProcCmdLine containsCIS " -P " OR TgtProcCmdLine containsCIS " -R " OR TgtProcCmdLine containsCIS " -pw " OR TgtProcCmdLine containsCIS " -ssh ")))

```