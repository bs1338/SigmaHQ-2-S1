# proc_creation_win_lolbin_extrac32

## Title
Suspicious Extrac32 Execution

## ID
aa8e035d-7be4-48d3-a944-102aec04400d

## Author
frack113

## Date
2021-11-26

## Tags
attack.command-and-control, attack.t1105

## Description
Download or Copy file with Extrac32

## References
https://lolbas-project.github.io/lolbas/Binaries/Extrac32/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS ".cab" AND (TgtProcCmdLine containsCIS "extrac32.exe" OR TgtProcImagePath endswithCIS "\extrac32.exe") AND (TgtProcCmdLine containsCIS "/C" OR TgtProcCmdLine containsCIS "/Y" OR TgtProcCmdLine containsCIS " \\")))

```