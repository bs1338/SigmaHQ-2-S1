# proc_creation_win_sysinternals_procdump_evasion

## Title
Potential SysInternals ProcDump Evasion

## ID
79b06761-465f-4f88-9ef2-150e24d3d737

## Author
Florian Roth (Nextron Systems)

## Date
2022-01-11

## Tags
attack.defense-evasion, attack.t1036, attack.t1003.001

## Description
Detects uses of the SysInternals ProcDump utility in which ProcDump or its output get renamed, or a dump file is moved or copied to a different name

## References
https://twitter.com/mrd0x/status/1480785527901204481

## False Positives
False positives are expected in cases in which ProcDump just gets copied to a different directory without any renaming

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "copy procdump" OR TgtProcCmdLine containsCIS "move procdump") OR ((TgtProcCmdLine containsCIS "2.dmp" OR TgtProcCmdLine containsCIS "lsass" OR TgtProcCmdLine containsCIS "out.dmp") AND (TgtProcCmdLine containsCIS "copy " AND TgtProcCmdLine containsCIS ".dmp ")) OR (TgtProcCmdLine containsCIS "copy lsass.exe_" OR TgtProcCmdLine containsCIS "move lsass.exe_")))

```