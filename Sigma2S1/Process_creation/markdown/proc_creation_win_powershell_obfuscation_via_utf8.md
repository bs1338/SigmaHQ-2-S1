# proc_creation_win_powershell_obfuscation_via_utf8

## Title
Potential PowerShell Obfuscation Via WCHAR

## ID
e312efd0-35a1-407f-8439-b8d434b438a6

## Author
Florian Roth (Nextron Systems)

## Date
2020-07-09

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1027

## Description
Detects suspicious encoded character syntax often used for defense evasion

## References
https://twitter.com/0gtweet/status/1281103918693482496

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine containsCIS "(WCHAR)0x")

```