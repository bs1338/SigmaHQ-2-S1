# proc_creation_win_fltmc_unload_driver_sysmon

## Title
Sysmon Driver Unloaded Via Fltmc.EXE

## ID
4d7cda18-1b12-4e52-b45c-d28653210df8

## Author
Kirill Kiryanov, oscd.community

## Date
2019-10-23

## Tags
attack.defense-evasion, attack.t1070, attack.t1562, attack.t1562.002

## Description
Detects possible Sysmon filter driver unloaded via fltmc.exe

## References
https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "unload" AND TgtProcCmdLine containsCIS "sysmon") AND TgtProcImagePath endswithCIS "\fltMC.exe"))

```