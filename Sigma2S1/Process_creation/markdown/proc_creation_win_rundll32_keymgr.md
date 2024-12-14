# proc_creation_win_rundll32_keymgr

## Title
Suspicious Key Manager Access

## ID
a4694263-59a8-4608-a3a0-6f8d3a51664c

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-21

## Tags
attack.credential-access, attack.t1555.004

## Description
Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)

## References
https://twitter.com/NinjaParanoid/status/1516442028963659777

## False Positives
Administrative activity

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "keymgr" AND TgtProcCmdLine containsCIS "KRShowKeyMgr") AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```