# proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta

## Title
Invoke-Obfuscation Via Use MSHTA

## ID
ac20ae82-8758-4f38-958e-b44a3140ca88

## Author
Nikita Nazarov, oscd.community

## Date
2020-10-08

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated Powershell via use MSHTA in Scripts

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "set" AND TgtProcCmdLine containsCIS "&&" AND TgtProcCmdLine containsCIS "mshta" AND TgtProcCmdLine containsCIS "vbscript:createobject" AND TgtProcCmdLine containsCIS ".run" AND TgtProcCmdLine containsCIS "(window.close)"))

```