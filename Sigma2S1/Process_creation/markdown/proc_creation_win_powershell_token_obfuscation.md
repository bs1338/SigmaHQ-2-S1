# proc_creation_win_powershell_token_obfuscation

## Title
Powershell Token Obfuscation - Process Creation

## ID
deb9b646-a508-44ee-b7c9-d8965921c6b6

## Author
frack113

## Date
2022-12-27

## Tags
attack.defense-evasion, attack.t1027.009

## Description
Detects TOKEN OBFUSCATION technique from Invoke-Obfuscation

## References
https://github.com/danielbohannon/Invoke-Obfuscation

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine RegExp "\\w+`(\\w+|-|.)`[\\w+|\\s]" OR TgtProcCmdLine RegExp ""(\\{\\d\\})+"\\s*-f" OR TgtProcCmdLine RegExp "(?i)\\$\\{`?e`?n`?v`?:`?p`?a`?t`?h`?\\}") AND (NOT TgtProcCmdLine containsCIS "${env:path}")))

```