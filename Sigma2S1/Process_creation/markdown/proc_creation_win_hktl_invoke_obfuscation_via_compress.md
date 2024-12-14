# proc_creation_win_hktl_invoke_obfuscation_via_compress

## Title
Invoke-Obfuscation COMPRESS OBFUSCATION

## ID
7eedcc9d-9fdb-4d94-9c54-474e8affc0c7

## Author
Timur Zinniatullin, oscd.community

## Date
2020-10-18

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated Powershell via COMPRESS OBFUSCATION

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "system.io.compression.deflatestream" OR TgtProcCmdLine containsCIS "system.io.streamreader" OR TgtProcCmdLine containsCIS "readtoend(") AND (TgtProcCmdLine containsCIS "new-object" AND TgtProcCmdLine containsCIS "text.encoding]::ascii")))

```