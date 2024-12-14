# proc_creation_win_control_panel_item

## Title
Control Panel Items

## ID
0ba863e6-def5-4e50-9cea-4dd8c7dc46a4

## Author
Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)

## Date
2020-06-22

## Tags
attack.execution, attack.defense-evasion, attack.t1218.002, attack.persistence, attack.t1546

## Description
Detects the malicious use of a control panel item

## References
https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "add" AND TgtProcCmdLine containsCIS "CurrentVersion\Control Panel\CPLs") AND TgtProcImagePath endswithCIS "\reg.exe") OR (TgtProcCmdLine endswithCIS ".cpl" AND (NOT ((TgtProcCmdLine containsCIS "regsvr32 " AND TgtProcCmdLine containsCIS " /s " AND TgtProcCmdLine containsCIS "igfxCPL.cpl") OR (TgtProcCmdLine containsCIS "\System32\" OR TgtProcCmdLine containsCIS "%System%" OR TgtProcCmdLine containsCIS "|C:\Windows\system32|"))))))

```