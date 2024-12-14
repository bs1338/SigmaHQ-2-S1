# proc_creation_win_regini_ads

## Title
Suspicious Registry Modification From ADS Via Regini.EXE

## ID
77946e79-97f1-45a2-84b4-f37b5c0d8682

## Author
Eli Salem, Sander Wiebing, oscd.community

## Date
2020-10-12

## Tags
attack.t1112, attack.defense-evasion

## Description
Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.

## References
https://lolbas-project.github.io/lolbas/Binaries/Regini/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regini.exe" AND TgtProcCmdLine RegExp ":[^ \\\\]"))

```