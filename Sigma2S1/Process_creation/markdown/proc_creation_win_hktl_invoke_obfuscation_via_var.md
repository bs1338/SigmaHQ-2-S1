# proc_creation_win_hktl_invoke_obfuscation_via_var

## Title
Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION

## ID
e9f55347-2928-4c06-88e5-1a7f8169942e

## Author
Timur Zinniatullin, oscd.community

## Date
2020-10-13

## Tags
attack.defense-evasion, attack.t1027, attack.execution, attack.t1059.001

## Description
Detects Obfuscated Powershell via VAR++ LAUNCHER

## References
https://github.com/SigmaHQ/sigma/issues/1009

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "{0}" OR TgtProcCmdLine containsCIS "{1}" OR TgtProcCmdLine containsCIS "{2}" OR TgtProcCmdLine containsCIS "{3}" OR TgtProcCmdLine containsCIS "{4}" OR TgtProcCmdLine containsCIS "{5}") AND (TgtProcCmdLine containsCIS "&&set" AND TgtProcCmdLine containsCIS "cmd" AND TgtProcCmdLine containsCIS "/c" AND TgtProcCmdLine containsCIS "-f")))

```