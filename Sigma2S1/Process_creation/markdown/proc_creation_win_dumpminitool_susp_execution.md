# proc_creation_win_dumpminitool_susp_execution

## Title
Suspicious DumpMinitool Execution

## ID
eb1c4225-1c23-4241-8dd4-051389fde4ce

## Author
Florian Roth (Nextron Systems)

## Date
2022-04-06

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects suspicious ways to use the "DumpMinitool.exe" binary

## References
https://twitter.com/mrd0x/status/1511415432888131586
https://twitter.com/mrd0x/status/1511489821247684615
https://lolbas-project.github.io/lolbas/OtherMSBinaries/DumpMinitool/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\DumpMinitool.exe" OR TgtProcImagePath endswithCIS "\DumpMinitool.x86.exe" OR TgtProcImagePath endswithCIS "\DumpMinitool.arm64.exe") AND ((NOT (TgtProcImagePath containsCIS "\Microsoft Visual Studio\" OR TgtProcImagePath containsCIS "\Extensions\")) OR TgtProcCmdLine containsCIS ".txt" OR ((TgtProcCmdLine containsCIS " Full" OR TgtProcCmdLine containsCIS " Mini" OR TgtProcCmdLine containsCIS " WithHeap") AND (NOT TgtProcCmdLine containsCIS "--dumpType")))))

```