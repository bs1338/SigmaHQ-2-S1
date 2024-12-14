# proc_creation_win_lolbin_ttdinject

## Title
Use of TTDInject.exe

## ID
b27077d6-23e6-45d2-81a0-e2b356eea5fd

## Author
frack113

## Date
2022-05-16

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects the executiob of TTDInject.exe, which is used by Windows 10 v1809 and newer to debug time travel (underlying call of tttracer.exe)

## References
https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcImagePath endswithCIS "ttdinject.exe")

```