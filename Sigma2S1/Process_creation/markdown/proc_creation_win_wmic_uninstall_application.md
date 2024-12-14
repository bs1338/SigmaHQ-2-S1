# proc_creation_win_wmic_uninstall_application

## Title
Application Removed Via Wmic.EXE

## ID
b53317a0-8acf-4fd1-8de8-a5401e776b96

## Author
frack113

## Date
2022-01-28

## Tags
attack.execution, attack.t1047

## Description
Detects the removal or uninstallation of an application via "Wmic.EXE".

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "call" AND TgtProcCmdLine containsCIS "uninstall") AND TgtProcImagePath endswithCIS "\WMIC.exe"))

```