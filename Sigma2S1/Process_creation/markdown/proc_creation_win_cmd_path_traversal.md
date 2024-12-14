# proc_creation_win_cmd_path_traversal

## Title
Potential CommandLine Path Traversal Via Cmd.EXE

## ID
087790e3-3287-436c-bccf-cbd0184a7db1

## Author
xknow @xknow_infosec, Tim Shelton

## Date
2020-06-11

## Tags
attack.execution, attack.t1059.003

## Description
Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking

## References
https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/
https://twitter.com/Oddvarmoe/status/1270633613449723905

## False Positives
Java tools are known to produce false-positive when loading libraries

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((((SrcProcCmdLine containsCIS "/c" OR SrcProcCmdLine containsCIS "/k" OR SrcProcCmdLine containsCIS "/r") OR (TgtProcCmdLine containsCIS "/c" OR TgtProcCmdLine containsCIS "/k" OR TgtProcCmdLine containsCIS "/r")) AND (SrcProcImagePath endswithCIS "\cmd.exe" OR TgtProcImagePath endswithCIS "\cmd.exe") AND (SrcProcCmdLine = "/../../" OR TgtProcCmdLine containsCIS "/../../")) AND (NOT TgtProcCmdLine containsCIS "\Tasktop\keycloak\bin\/../../jre\bin\java")))

```