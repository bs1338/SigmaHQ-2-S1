# proc_creation_win_hktl_sharp_dpapi_execution

## Title
HackTool - SharpDPAPI Execution

## ID
c7d33b50-f690-4b51-8cfb-0fb912a31e57

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-06-26

## Tags
attack.privilege-escalation, attack.defense-evasion, attack.t1134.001, attack.t1134.003

## Description
Detects the execution of the SharpDPAPI tool based on CommandLine flags and PE metadata.
SharpDPAPI is a C# port of some DPAPI functionality from the Mimikatz project.


## References
https://github.com/GhostPack/SharpDPAPI

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\SharpDPAPI.exe" OR ((TgtProcCmdLine containsCIS " backupkey " OR TgtProcCmdLine containsCIS " blob " OR TgtProcCmdLine containsCIS " certificates " OR TgtProcCmdLine containsCIS " credentials " OR TgtProcCmdLine containsCIS " keepass " OR TgtProcCmdLine containsCIS " masterkeys " OR TgtProcCmdLine containsCIS " rdg " OR TgtProcCmdLine containsCIS " vaults ") AND ((TgtProcCmdLine containsCIS " /file:" OR TgtProcCmdLine containsCIS " /machine" OR TgtProcCmdLine containsCIS " /mkfile:" OR TgtProcCmdLine containsCIS " /password:" OR TgtProcCmdLine containsCIS " /pvk:" OR TgtProcCmdLine containsCIS " /server:" OR TgtProcCmdLine containsCIS " /target:" OR TgtProcCmdLine containsCIS " /unprotect") OR (TgtProcCmdLine containsCIS " {" AND TgtProcCmdLine containsCIS "}:")))))

```