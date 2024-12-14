# proc_creation_win_odbcconf_driver_install_susp

## Title
Suspicious Driver/DLL Installation Via Odbcconf.EXE

## ID
cb0fe7c5-f3a3-484d-aa25-d350a7912729

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-23

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with the "INSTALLDRIVER" action where the driver doesn't contain a ".dll" extension. This is often used as a defense evasion method.

## References
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://web.archive.org/web/20191023232753/https://twitter.com/Hexacorn/status/1187143326673330176
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "INSTALLDRIVER " AND TgtProcImagePath endswithCIS "\odbcconf.exe") AND (NOT TgtProcCmdLine containsCIS ".dll")))

```