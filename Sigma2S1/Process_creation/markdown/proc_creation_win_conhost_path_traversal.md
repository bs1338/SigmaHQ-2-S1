# proc_creation_win_conhost_path_traversal

## Title
Conhost.exe CommandLine Path Traversal

## ID
ee5e119b-1f75-4b34-add8-3be976961e39

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-14

## Tags
attack.execution, attack.t1059.003

## Description
detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking

## References
https://pentestlab.blog/2020/07/06/indirect-command-execution/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "/../../" AND SrcProcCmdLine containsCIS "conhost"))

```