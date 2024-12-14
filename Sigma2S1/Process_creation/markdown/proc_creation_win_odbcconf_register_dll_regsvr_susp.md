# proc_creation_win_odbcconf_register_dll_regsvr_susp

## Title
Potentially Suspicious DLL Registered Via Odbcconf.EXE

## ID
ba4cfc11-d0fa-4d94-bf20-7c332c412e76

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with the "REGSVR" action where the DLL in question doesn't contain a ".dll" extension. Which is often used as a method to evade defenses.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "REGSVR " AND TgtProcImagePath endswithCIS "\odbcconf.exe") AND (NOT TgtProcCmdLine containsCIS ".dll")))

```