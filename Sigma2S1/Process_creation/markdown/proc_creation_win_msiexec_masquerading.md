# proc_creation_win_msiexec_masquerading

## Title
Potential MsiExec Masquerading

## ID
e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144

## Author
Florian Roth (Nextron Systems)

## Date
2019-11-14

## Tags
attack.defense-evasion, attack.t1036.005

## Description
Detects the execution of msiexec.exe from an uncommon directory

## References
https://twitter.com/200_okay_/status/1194765831911215104

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\msiexec.exe" AND (NOT (TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\" OR TgtProcImagePath startswithCIS "C:\Windows\WinSxS\"))))

```