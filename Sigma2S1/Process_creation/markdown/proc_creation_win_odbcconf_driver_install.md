# proc_creation_win_odbcconf_driver_install

## Title
Driver/DLL Installation Via Odbcconf.EXE

## ID
3f5491e2-8db8-496b-9e95-1029fce852d4

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with "INSTALLDRIVER" which installs a new ODBC driver. Attackers abuse this to install and run malicious DLLs.

## References
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://web.archive.org/web/20191023232753/https://twitter.com/Hexacorn/status/1187143326673330176
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/

## False Positives
Legitimate driver DLLs being registered via "odbcconf" will generate false positives. Investigate the path of the DLL and its contents to determine if the action is authorized.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "INSTALLDRIVER " AND TgtProcCmdLine containsCIS ".dll") AND TgtProcImagePath endswithCIS "\odbcconf.exe"))

```