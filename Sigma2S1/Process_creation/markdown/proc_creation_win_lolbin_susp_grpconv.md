# proc_creation_win_lolbin_susp_grpconv

## Title
Suspicious GrpConv Execution

## ID
f14e169e-9978-4c69-acb3-1cff8200bc36

## Author
Florian Roth (Nextron Systems)

## Date
2022-05-19

## Tags
attack.persistence, attack.t1547

## Description
Detects the suspicious execution of a utility to convert Windows 3.x .grp files or for persistence purposes by malicious software or actors

## References
https://twitter.com/0gtweet/status/1526833181831200770

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "grpconv.exe -o" OR TgtProcCmdLine containsCIS "grpconv -o"))

```