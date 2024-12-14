# proc_creation_win_tscon_rdp_redirect

## Title
Suspicious RDP Redirect Using TSCON

## ID
f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb

## Author
Florian Roth (Nextron Systems)

## Date
2018-03-17

## Tags
attack.lateral-movement, attack.t1563.002, attack.t1021.001, car.2013-07-002

## Description
Detects a suspicious RDP session redirect using tscon.exe

## References
http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
https://www.hackingarticles.in/rdp-session-hijacking-with-tscon/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS " /dest:rdp-tcp#")

```