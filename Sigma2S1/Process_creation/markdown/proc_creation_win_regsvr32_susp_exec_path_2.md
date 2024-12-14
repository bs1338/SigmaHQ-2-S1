# proc_creation_win_regsvr32_susp_exec_path_2

## Title
Regsvr32 Execution From Highly Suspicious Location

## ID
327ff235-94eb-4f06-b9de-aaee571324be

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-26

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects execution of regsvr32 where the DLL is located in a highly suspicious locations

## References
Internal Research

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\regsvr32.exe" AND ((TgtProcCmdLine containsCIS ":\PerfLogs\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS "\Windows\Registration\CRMLog" OR TgtProcCmdLine containsCIS "\Windows\System32\com\dmp\" OR TgtProcCmdLine containsCIS "\Windows\System32\FxsTmp\" OR TgtProcCmdLine containsCIS "\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\" OR TgtProcCmdLine containsCIS "\Windows\System32\spool\drivers\color\" OR TgtProcCmdLine containsCIS "\Windows\System32\spool\PRINTERS\" OR TgtProcCmdLine containsCIS "\Windows\System32\spool\SERVERS\" OR TgtProcCmdLine containsCIS "\Windows\System32\Tasks_Migrated\" OR TgtProcCmdLine containsCIS "\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\" OR TgtProcCmdLine containsCIS "\Windows\SysWOW64\com\dmp\" OR TgtProcCmdLine containsCIS "\Windows\SysWOW64\FxsTmp\" OR TgtProcCmdLine containsCIS "\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\" OR TgtProcCmdLine containsCIS "\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\" OR TgtProcCmdLine containsCIS "\Windows\Tasks\" OR TgtProcCmdLine containsCIS "\Windows\Tracing\") OR ((TgtProcCmdLine containsCIS " \"C:\" OR TgtProcCmdLine containsCIS " C:\" OR TgtProcCmdLine containsCIS " 'C:\" OR TgtProcCmdLine containsCIS "D:\") AND (NOT (TgtProcCmdLine containsCIS "C:\Program Files (x86)\" OR TgtProcCmdLine containsCIS "C:\Program Files\" OR TgtProcCmdLine containsCIS "C:\ProgramData\" OR TgtProcCmdLine containsCIS "C:\Users\" OR TgtProcCmdLine containsCIS " C:\Windows\" OR TgtProcCmdLine containsCIS " \"C:\Windows\" OR TgtProcCmdLine containsCIS " 'C:\Windows\")))) AND (NOT (TgtProcCmdLine = "" OR TgtProcCmdLine IS NOT EMPTY))))

```