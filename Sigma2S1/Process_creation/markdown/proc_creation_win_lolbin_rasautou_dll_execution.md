# proc_creation_win_lolbin_rasautou_dll_execution

## Title
DLL Execution via Rasautou.exe

## ID
cd3d1298-eb3b-476c-ac67-12847de55813

## Author
Julia Fomina, oscd.community

## Date
2020-10-09

## Tags
attack.defense-evasion, attack.t1218

## Description
Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p.

## References
https://lolbas-project.github.io/lolbas/Binaries/Rasautou/
https://github.com/fireeye/DueDLLigence
https://www.fireeye.com/blog/threat-research/2019/10/staying-hidden-on-the-endpoint-evading-detection-with-shellcode.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -d " AND TgtProcCmdLine containsCIS " -p ") AND TgtProcImagePath endswithCIS "\rasautou.exe"))

```