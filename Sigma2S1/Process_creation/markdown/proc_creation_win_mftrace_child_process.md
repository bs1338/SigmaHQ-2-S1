# proc_creation_win_mftrace_child_process

## Title
Potential Mftrace.EXE Abuse

## ID
3d48c9d3-1aa6-418d-98d3-8fd3c01a564e

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-09

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects child processes of the "Trace log generation tool for Media Foundation Tools" (Mftrace.exe) which can abused to execute arbitrary binaries.

## References
https://lolbas-project.github.io/lolbas/OtherMSBinaries/Mftrace/

## False Positives
Legitimate use for tracing purposes

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\mftrace.exe")

```