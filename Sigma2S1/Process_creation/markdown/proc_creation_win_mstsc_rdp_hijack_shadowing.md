# proc_creation_win_mstsc_rdp_hijack_shadowing

## Title
Potential MSTSC Shadowing Activity

## ID
6ba5a05f-b095-4f0a-8654-b825f4f16334

## Author
Florian Roth (Nextron Systems)

## Date
2020-01-24

## Tags
attack.lateral-movement, attack.t1563.002

## Description
Detects RDP session hijacking by using MSTSC shadowing

## References
https://twitter.com/kmkz_security/status/1220694202301976576
https://github.com/kmkz/Pentesting/blob/47592e5e160d3b86c2024f09ef04ceb87d204995/Post-Exploitation-Cheat-Sheet

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "noconsentprompt" AND TgtProcCmdLine containsCIS "shadow:"))

```