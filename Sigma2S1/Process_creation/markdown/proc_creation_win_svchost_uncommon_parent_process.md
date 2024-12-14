# proc_creation_win_svchost_uncommon_parent_process

## Title
Uncommon Svchost Parent Process

## ID
01d2e2a1-5f09-44f7-9fc1-24faa7479b6d

## Author
Florian Roth (Nextron Systems)

## Date
2017-08-15

## Tags
attack.defense-evasion, attack.t1036.005

## Description
Detects an uncommon svchost parent process

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\svchost.exe" AND (NOT ((SrcProcImagePath endswithCIS "\Mrt.exe" OR SrcProcImagePath endswithCIS "\MsMpEng.exe" OR SrcProcImagePath endswithCIS "\ngen.exe" OR SrcProcImagePath endswithCIS "\rpcnet.exe" OR SrcProcImagePath endswithCIS "\services.exe" OR SrcProcImagePath endswithCIS "\TiWorker.exe") OR (SrcProcImagePath In Contains AnyCase ("-","")) OR SrcProcImagePath IS NOT EMPTY))))

```