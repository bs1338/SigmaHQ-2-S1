# proc_creation_win_tscon_localsystem

## Title
Suspicious TSCON Start as SYSTEM

## ID
9847f263-4a81-424f-970c-875dab15b79b

## Author
Florian Roth (Nextron Systems)

## Date
2018-03-17

## Tags
attack.command-and-control, attack.t1219

## Description
Detects a tscon.exe start as LOCAL SYSTEM

## References
http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\tscon.exe" AND (TgtProcUser containsCIS "AUTHORI" OR TgtProcUser containsCIS "AUTORI")))

```