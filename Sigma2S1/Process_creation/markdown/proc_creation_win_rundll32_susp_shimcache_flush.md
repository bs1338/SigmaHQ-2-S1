# proc_creation_win_rundll32_susp_shimcache_flush

## Title
ShimCache Flush

## ID
b0524451-19af-4efa-a46f-562a977f792e

## Author
Florian Roth (Nextron Systems)

## Date
2021-02-01

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects actions that clear the local ShimCache and remove forensic evidence

## References
https://medium.com/@blueteamops/shimcache-flush-89daff28d15e

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "rundll32" AND TgtProcCmdLine containsCIS "apphelp.dll") AND (TgtProcCmdLine containsCIS "ShimFlushCache" OR TgtProcCmdLine containsCIS "#250")) OR ((TgtProcCmdLine containsCIS "rundll32" AND TgtProcCmdLine containsCIS "kernel32.dll") AND (TgtProcCmdLine containsCIS "BaseFlushAppcompatCache" OR TgtProcCmdLine containsCIS "#46"))))

```