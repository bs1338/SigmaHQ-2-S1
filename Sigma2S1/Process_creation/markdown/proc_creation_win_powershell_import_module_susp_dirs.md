# proc_creation_win_powershell_import_module_susp_dirs

## Title
Import PowerShell Modules From Suspicious Directories - ProcCreation

## ID
c31364f7-8be6-4b77-8483-dd2b5a7b69a3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-01-10

## Tags
attack.execution, attack.t1059.001

## Description
Detects powershell scripts that import modules from suspicious directories

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "Import-Module \"$Env:Temp\" OR TgtProcCmdLine containsCIS "Import-Module '$Env:Temp\" OR TgtProcCmdLine containsCIS "Import-Module $Env:Temp\" OR TgtProcCmdLine containsCIS "Import-Module \"$Env:Appdata\" OR TgtProcCmdLine containsCIS "Import-Module '$Env:Appdata\" OR TgtProcCmdLine containsCIS "Import-Module $Env:Appdata\" OR TgtProcCmdLine containsCIS "Import-Module C:\Users\Public\" OR TgtProcCmdLine containsCIS "ipmo \"$Env:Temp\" OR TgtProcCmdLine containsCIS "ipmo '$Env:Temp\" OR TgtProcCmdLine containsCIS "ipmo $Env:Temp\" OR TgtProcCmdLine containsCIS "ipmo \"$Env:Appdata\" OR TgtProcCmdLine containsCIS "ipmo '$Env:Appdata\" OR TgtProcCmdLine containsCIS "ipmo $Env:Appdata\" OR TgtProcCmdLine containsCIS "ipmo C:\Users\Public\"))

```