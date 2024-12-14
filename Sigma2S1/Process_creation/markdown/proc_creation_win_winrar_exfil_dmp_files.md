# proc_creation_win_winrar_exfil_dmp_files

## Title
Winrar Compressing Dump Files

## ID
1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-04

## Tags
attack.collection, attack.t1560.001

## Description
Detects execution of WinRAR in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.

## References
https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/

## False Positives
Legitimate use of WinRAR with a command line in which ".dmp" or ".dump" appears accidentally
Legitimate use of WinRAR to compress WER ".dmp" files for troubleshooting

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".dmp" OR TgtProcCmdLine containsCIS ".dump" OR TgtProcCmdLine containsCIS ".hdmp") AND ((TgtProcImagePath endswithCIS "\rar.exe" OR TgtProcImagePath endswithCIS "\winrar.exe") OR TgtProcDisplayName = "Command line RAR")))

```