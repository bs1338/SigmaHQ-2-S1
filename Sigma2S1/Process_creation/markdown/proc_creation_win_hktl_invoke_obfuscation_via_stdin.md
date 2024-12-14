# proc_creation_win_hktl_invoke_obfuscation_via_stdin

## Title
Invoke-Obfuscation Via Stdin

## ID
9c14c9fa-1a63-4a64-8e57-d19280559490

## Author
Nikita Nazarov, oscd.community

## Date
2020-10-12

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated Powershell via Stdin in Scripts

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND TgtProcCmdLine RegExp "(?i)(set).*&&\\s?set.*(environment|invoke|\\$\\{?input).*&&.*"")

```