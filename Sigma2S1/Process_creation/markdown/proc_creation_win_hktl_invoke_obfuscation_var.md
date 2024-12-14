# proc_creation_win_hktl_invoke_obfuscation_var

## Title
Invoke-Obfuscation VAR+ Launcher

## ID
27aec9c9-dbb0-4939-8422-1742242471d0

## Author
Jonathan Cheong, oscd.community

## Date
2020-10-15

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated use of Environment Variables to execute PowerShell

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine RegExp "cmd.{0,5}(?:/c|/r)(?:\\s|)\\"set\\s[a-zA-Z]{3,6}.*(?:\\{\\d\\}){1,}\\\\\\"\\s+?\\-f(?:.*\\)){1,}.*\\"")

```