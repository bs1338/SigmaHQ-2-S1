# proc_creation_win_hktl_sharpersist

## Title
HackTool - SharPersist Execution

## ID
26488ad0-f9fd-4536-876f-52fea846a2e4

## Author
Florian Roth (Nextron Systems)

## Date
2022-09-15

## Tags
attack.persistence, attack.t1053

## Description
Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms

## References
https://www.mandiant.com/resources/blog/sharpersist-windows-persistence-toolkit
https://github.com/mandiant/SharPersist

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -t schtask -c " OR TgtProcCmdLine containsCIS " -t startupfolder -c ") OR (TgtProcCmdLine containsCIS " -t reg -c " AND TgtProcCmdLine containsCIS " -m add") OR (TgtProcCmdLine containsCIS " -t service -c " AND TgtProcCmdLine containsCIS " -m add") OR (TgtProcCmdLine containsCIS " -t schtask -c " AND TgtProcCmdLine containsCIS " -m add") OR (TgtProcImagePath endswithCIS "\SharPersist.exe" OR TgtProcDisplayName = "SharPersist")))

```