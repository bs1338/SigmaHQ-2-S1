# proc_creation_win_powershell_public_folder

## Title
Execution of Powershell Script in Public Folder

## ID
fb9d3ff7-7348-46ab-af8c-b55f5fbf39b4

## Author
Max Altgelt (Nextron Systems)

## Date
2022-04-06

## Tags
attack.execution, attack.t1059.001

## Description
This rule detects execution of PowerShell scripts located in the "C:\Users\Public" folder

## References
https://www.mandiant.com/resources/evolution-of-fin7

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "-f C:\Users\Public" OR TgtProcCmdLine containsCIS "-f \"C:\Users\Public" OR TgtProcCmdLine containsCIS "-f %Public%" OR TgtProcCmdLine containsCIS "-fi C:\Users\Public" OR TgtProcCmdLine containsCIS "-fi \"C:\Users\Public" OR TgtProcCmdLine containsCIS "-fi %Public%" OR TgtProcCmdLine containsCIS "-fil C:\Users\Public" OR TgtProcCmdLine containsCIS "-fil \"C:\Users\Public" OR TgtProcCmdLine containsCIS "-fil %Public%" OR TgtProcCmdLine containsCIS "-file C:\Users\Public" OR TgtProcCmdLine containsCIS "-file \"C:\Users\Public" OR TgtProcCmdLine containsCIS "-file %Public%") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")))

```