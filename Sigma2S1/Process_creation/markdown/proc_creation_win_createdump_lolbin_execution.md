# proc_creation_win_createdump_lolbin_execution

## Title
CreateDump Process Dump

## ID
515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2022-01-04

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects uses of the createdump.exe LOLOBIN utility to dump process memory

## References
https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
https://twitter.com/bopin2020/status/1366400799199272960

## False Positives
Command lines that use the same flags

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -u " OR TgtProcCmdLine containsCIS " --full " OR TgtProcCmdLine containsCIS " -f " OR TgtProcCmdLine containsCIS " --name " OR TgtProcCmdLine containsCIS ".dmp ") AND TgtProcImagePath endswithCIS "\createdump.exe"))

```