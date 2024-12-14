# proc_creation_win_print_remote_file_copy

## Title
Abusing Print Executable

## ID
bafac3d6-7de9-4dd9-8874-4a1194b493ed

## Author
Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative

## Date
2020-10-05

## Tags
attack.defense-evasion, attack.t1218

## Description
Attackers can use print.exe for remote file copy

## References
https://lolbas-project.github.io/lolbas/Binaries/Print/
https://twitter.com/Oddvarmoe/status/985518877076541440

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "/D" AND TgtProcCmdLine containsCIS ".exe") AND TgtProcCmdLine startswithCIS "print" AND TgtProcImagePath endswithCIS "\print.exe") AND (NOT TgtProcCmdLine containsCIS "print.exe")))

```