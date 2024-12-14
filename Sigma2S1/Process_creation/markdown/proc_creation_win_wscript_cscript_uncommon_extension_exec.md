# proc_creation_win_wscript_cscript_uncommon_extension_exec

## Title
Cscript/Wscript Uncommon Script Extension Execution

## ID
99b7460d-c9f1-40d7-a316-1f36f61d52ee

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-15

## Tags
attack.execution, attack.t1059.005, attack.t1059.007

## Description
Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension

## References
Internal Research

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".csv" OR TgtProcCmdLine containsCIS ".dat" OR TgtProcCmdLine containsCIS ".doc" OR TgtProcCmdLine containsCIS ".gif" OR TgtProcCmdLine containsCIS ".jpeg" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".ppt" OR TgtProcCmdLine containsCIS ".txt" OR TgtProcCmdLine containsCIS ".xls" OR TgtProcCmdLine containsCIS ".xml") AND (TgtProcImagePath endswithCIS "\wscript.exe" OR TgtProcImagePath endswithCIS "\cscript.exe")))

```