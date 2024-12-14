# proc_creation_win_hktl_dinjector

## Title
HackTool - DInjector PowerShell Cradle Execution

## ID
d78b5d61-187d-44b6-bf02-93486a80de5a

## Author
Florian Roth (Nextron Systems)

## Date
2021-12-07

## Tags
attack.defense-evasion, attack.t1055

## Description
Detects the use of the Dinject PowerShell cradle based on the specific flags

## References
https://web.archive.org/web/20211001064856/https://github.com/snovvcrash/DInjector

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " /am51" AND TgtProcCmdLine containsCIS " /password"))

```