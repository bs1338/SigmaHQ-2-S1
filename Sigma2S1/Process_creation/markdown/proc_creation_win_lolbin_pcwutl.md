# proc_creation_win_lolbin_pcwutl

## Title
Code Execution via Pcwutl.dll

## ID
9386d78a-7207-4048-9c9f-a93a7c2d1c05

## Author
Julia Fomina, oscd.community

## Date
2020-10-05

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.

## References
https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/
https://twitter.com/harr0ey/status/989617817849876488

## False Positives
Use of Program Compatibility Troubleshooter Helper

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "pcwutl" AND TgtProcCmdLine containsCIS "LaunchApplication") AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```