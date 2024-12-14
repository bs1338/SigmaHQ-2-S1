# proc_creation_win_ssh_rdp_tunneling

## Title
Potential RDP Tunneling Via SSH

## ID
f7d7ebd5-a016-46e2-9c54-f9932f2d386d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-10-12

## Tags
attack.command-and-control, attack.t1572

## Description
Execution of ssh.exe to perform data exfiltration and tunneling through RDP

## References
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ":3389" AND TgtProcImagePath endswithCIS "\ssh.exe"))

```