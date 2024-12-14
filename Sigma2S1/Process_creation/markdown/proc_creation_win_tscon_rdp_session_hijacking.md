# proc_creation_win_tscon_rdp_session_hijacking

## Title
Potential RDP Session Hijacking Activity

## ID
224f140f-3553-4cd1-af78-13d81bf9f7cc

## Author
@juju4

## Date
2022-12-27

## Tags
attack.execution

## Description
Detects potential RDP Session Hijacking activity on Windows systems

## References
https://twitter.com/Moti_B/status/909449115477659651

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\tscon.exe" AND (TgtProcIntegrityLevel In ("System","S-1-16-16384"))))

```