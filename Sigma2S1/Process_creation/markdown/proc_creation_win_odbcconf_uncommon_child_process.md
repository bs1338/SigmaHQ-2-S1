# proc_creation_win_odbcconf_uncommon_child_process

## Title
Uncommon Child Process Spawned By Odbcconf.EXE

## ID
8e3c7994-131e-4ba5-b6ea-804d49113a26

## Author
Harjot Singh @cyb3rjy0t

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects an uncommon child process of "odbcconf.exe" binary which normally shouldn't have any child processes.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://medium.com/@cyberjyot/t1218-008-dll-execution-using-odbcconf-exe-803fa9e08dac

## False Positives
In rare occurrences where "odbcconf" crashes. It might spawn a "werfault" process
Other child processes will depend on the DLL being registered by actions like "regsvr". In case where the DLLs have external calls (which should be rare). Other child processes might spawn and additional filters need to be applied.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND SrcProcImagePath endswithCIS "\odbcconf.exe")

```