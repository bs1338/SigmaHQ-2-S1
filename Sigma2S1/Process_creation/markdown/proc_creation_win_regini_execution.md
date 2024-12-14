# proc_creation_win_regini_execution

## Title
Registry Modification Via Regini.EXE

## ID
5f60740a-f57b-4e76-82a1-15b6ff2cb134

## Author
Eli Salem, Sander Wiebing, oscd.community

## Date
2020-10-08

## Tags
attack.t1112, attack.defense-evasion

## Description
Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.

## References
https://lolbas-project.github.io/lolbas/Binaries/Regini/
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regini

## False Positives
Legitimate modification of keys

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regini.exe" AND (NOT TgtProcCmdLine RegExp ":[^ \\\\]")))

```