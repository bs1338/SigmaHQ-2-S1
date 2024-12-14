# proc_creation_win_odbcconf_register_dll_regsvr

## Title
New DLL Registered Via Odbcconf.EXE

## ID
9f0a8bf3-a65b-440a-8c1e-5cb1547c8e70

## Author
Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with "REGSVR" in order to register a new DLL (equivalent to running regsvr32). Attackers abuse this to install and run malicious DLLs.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://redcanary.com/blog/raspberry-robin/
https://web.archive.org/web/20191023232753/https://twitter.com/Hexacorn/status/1187143326673330176
https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/
https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html

## False Positives
Legitimate DLLs being registered via "odbcconf" will generate false positives. Investigate the path of the DLL and its content to determine if the action is authorized.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "REGSVR " AND TgtProcCmdLine containsCIS ".dll") AND TgtProcImagePath endswithCIS "\odbcconf.exe"))

```