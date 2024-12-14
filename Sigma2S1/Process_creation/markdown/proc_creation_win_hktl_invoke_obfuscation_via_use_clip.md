# proc_creation_win_hktl_invoke_obfuscation_via_use_clip

## Title
Invoke-Obfuscation Via Use Clip

## ID
e1561947-b4e3-4a74-9bdd-83baed21bdb5

## Author
Nikita Nazarov, oscd.community

## Date
2020-10-09

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated Powershell via use Clip.exe in Scripts

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine RegExp "(?i)echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?)")

```