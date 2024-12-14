# proc_creation_win_hktl_invoke_obfuscation_stdin

## Title
Invoke-Obfuscation STDIN+ Launcher

## ID
6c96fc76-0eb1-11eb-adc1-0242ac120002

## Author
Jonathan Cheong, oscd.community

## Date
2020-10-15

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated use of stdin to execute PowerShell

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine RegExp "cmd.{0,5}(?:/c|/r).+powershell.+(?:\\$\\{?input\\}?|noexit).+\\"")

```