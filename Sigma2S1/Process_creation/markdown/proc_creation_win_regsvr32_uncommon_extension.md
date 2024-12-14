# proc_creation_win_regsvr32_uncommon_extension

## Title
Regsvr32 DLL Execution With Uncommon Extension

## ID
50919691-7302-437f-8e10-1fe088afa145

## Author
Florian Roth (Nextron Systems)

## Date
2019-07-17

## Tags
attack.defense-evasion, attack.t1574, attack.execution

## Description
Detects a "regsvr32" execution where the DLL doesn't contain a common file extension.

## References
https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/

## False Positives
Other legitimate extensions currently not in the list either from third party or specific Windows components.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regsvr32.exe" AND (NOT (TgtProcCmdLine = "" OR (TgtProcCmdLine containsCIS ".ax" OR TgtProcCmdLine containsCIS ".cpl" OR TgtProcCmdLine containsCIS ".dll" OR TgtProcCmdLine containsCIS ".ocx") OR TgtProcCmdLine IS NOT EMPTY)) AND (NOT (TgtProcCmdLine containsCIS ".bav" OR TgtProcCmdLine containsCIS ".ppl"))))

```