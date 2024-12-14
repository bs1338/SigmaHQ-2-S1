# proc_creation_win_kavremover_uncommon_execution

## Title
Kavremover Dropped Binary LOLBIN Usage

## ID
d047726b-c71c-4048-a99b-2e2f50dc107d

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-11-01

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.

## References
https://nasbench.medium.com/lolbined-using-kaspersky-endpoint-security-kes-installer-to-execute-arbitrary-commands-1c999f1b7fea

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " run run-cmd " AND (NOT (SrcProcImagePath endswithCIS "\cleanapi.exe" OR SrcProcImagePath endswithCIS "\kavremover.exe"))))

```