# proc_creation_win_mstsc_run_local_rdp_file_susp_location

## Title
Suspicious Mstsc.EXE Execution With Local RDP File

## ID
6e22722b-dfb1-4508-a911-49ac840b40f8

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-18

## Tags
attack.command-and-control, attack.t1219

## Description
Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.

## References
https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
https://web.archive.org/web/20230726144748/https://blog.thickmints.dev/mintsights/detecting-rogue-rdp/

## False Positives
Likelihood is related to how often the paths are used in the environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine endswithCIS ".rdp" OR TgtProcCmdLine endswithCIS ".rdp\"") AND TgtProcImagePath endswithCIS "\mstsc.exe" AND (TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\System32\spool\drivers\color" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks_Migrated " OR TgtProcCmdLine containsCIS ":\Windows\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\Tracing\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Downloads\")))

```