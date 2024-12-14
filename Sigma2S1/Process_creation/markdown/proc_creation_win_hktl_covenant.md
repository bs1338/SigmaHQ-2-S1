# proc_creation_win_hktl_covenant

## Title
HackTool - Covenant PowerShell Launcher

## ID
c260b6db-48ba-4b4a-a76f-2f67644e99d2

## Author
Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community

## Date
2020-06-04

## Tags
attack.execution, attack.defense-evasion, attack.t1059.001, attack.t1564.003

## Description
Detects suspicious command lines used in Covenant luanchers

## References
https://posts.specterops.io/covenant-v0-5-eee0507b85ba

## False Positives


## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-Command" OR TgtProcCmdLine containsCIS "-EncodedCommand") AND (TgtProcCmdLine containsCIS "-Sta" AND TgtProcCmdLine containsCIS "-Nop" AND TgtProcCmdLine containsCIS "-Window" AND TgtProcCmdLine containsCIS "Hidden")) OR (TgtProcCmdLine containsCIS "sv o (New-Object IO.MemorySteam);sv d " OR TgtProcCmdLine containsCIS "mshta file.hta" OR TgtProcCmdLine containsCIS "GruntHTTP" OR TgtProcCmdLine containsCIS "-EncodedCommand cwB2ACAAbwAgA")))

```