# proc_creation_win_odbcconf_exec_susp_locations

## Title
Odbcconf.EXE Suspicious DLL Location

## ID
6b65c28e-11f3-46cb-902a-68f2cafaf474

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" where the path of the DLL being registered is located in a potentially suspicious location.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html
https://securityintelligence.com/posts/raspberry-robin-worm-dridex-malware/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\ProgramData\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Registration\CRMLog" OR TgtProcCmdLine containsCIS ":\Windows\System32\com\dmp\" OR TgtProcCmdLine containsCIS ":\Windows\System32\FxsTmp\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\" OR TgtProcCmdLine containsCIS ":\Windows\System32\spool\drivers\color\" OR TgtProcCmdLine containsCIS ":\Windows\System32\spool\PRINTERS\" OR TgtProcCmdLine containsCIS ":\Windows\System32\spool\SERVERS\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks_Migrated\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\" OR TgtProcCmdLine containsCIS ":\Windows\SysWOW64\com\dmp\" OR TgtProcCmdLine containsCIS ":\Windows\SysWOW64\FxsTmp\" OR TgtProcCmdLine containsCIS ":\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\" OR TgtProcCmdLine containsCIS ":\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\" OR TgtProcCmdLine containsCIS ":\Windows\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\Tracing\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\") AND TgtProcImagePath endswithCIS "\odbcconf.exe"))

```