# proc_creation_win_renamed_createdump

## Title
Renamed CreateDump Utility Execution

## ID
1a1ed54a-2ba4-4221-94d5-01dee560d71e

## Author
Florian Roth (Nextron Systems)

## Date
2022-09-20

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects uses of a renamed legitimate createdump.exe LOLOBIN utility to dump process memory

## References
https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
https://twitter.com/bopin2020/status/1366400799199272960

## False Positives
Command lines that use the same flags

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -u " AND TgtProcCmdLine containsCIS " -f " AND TgtProcCmdLine containsCIS ".dmp") OR (TgtProcCmdLine containsCIS " --full " AND TgtProcCmdLine containsCIS " --name " AND TgtProcCmdLine containsCIS ".dmp")) AND (NOT TgtProcImagePath endswithCIS "\createdump.exe")))

```