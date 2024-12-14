# proc_creation_win_gup_arbitrary_binary_execution

## Title
Arbitrary Binary Execution Using GUP Utility

## ID
d65aee4d-2292-4cea-b832-83accd6cfa43

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-06-10

## Tags
attack.execution

## Description
Detects execution of the Notepad++ updater (gup) to launch other commands or executables

## References
https://twitter.com/nas_bench/status/1535322445439180803

## False Positives
Other parent binaries using GUP not currently identified

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\explorer.exe" AND SrcProcImagePath endswithCIS "\gup.exe") AND (NOT ((TgtProcCmdLine containsCIS "\Notepad++\notepad++.exe" AND TgtProcImagePath endswithCIS "\explorer.exe") OR TgtProcCmdLine IS NOT EMPTY OR SrcProcImagePath containsCIS "\Notepad++\updater\"))))

```