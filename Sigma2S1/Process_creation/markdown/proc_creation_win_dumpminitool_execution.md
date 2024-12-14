# proc_creation_win_dumpminitool_execution

## Title
DumpMinitool Execution

## ID
dee0a7a3-f200-4112-a99b-952196d81e42

## Author
Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)

## Date
2022-04-06

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects the use of "DumpMinitool.exe" a tool that allows the dump of process memory via the use of the "MiniDumpWriteDump"

## References
https://twitter.com/mrd0x/status/1511415432888131586
https://twitter.com/mrd0x/status/1511489821247684615
https://lolbas-project.github.io/lolbas/OtherMSBinaries/DumpMinitool/
https://gist.github.com/nasbench/6d58c3c125e2fa1b8f7a09754c1b087f

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " Full" OR TgtProcCmdLine containsCIS " Mini" OR TgtProcCmdLine containsCIS " WithHeap") AND (TgtProcImagePath endswithCIS "\DumpMinitool.exe" OR TgtProcImagePath endswithCIS "\DumpMinitool.x86.exe" OR TgtProcImagePath endswithCIS "\DumpMinitool.arm64.exe")))

```