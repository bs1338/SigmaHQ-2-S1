# proc_creation_win_regsvr32_susp_exec_path_1

## Title
Regsvr32 Execution From Potential Suspicious Location

## ID
9525dc73-0327-438c-8c04-13c0e037e9da

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-26

## Tags
attack.defense-evasion, attack.t1218.010

## Description
Detects execution of regsvr32 where the DLL is located in a potentially suspicious location.

## References
https://web.archive.org/web/20171001085340/https://subt0x10.blogspot.com/2017/04/bypass-application-whitelisting-script.html
https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/

## False Positives
Some installers might execute "regsvr32" with DLLs located in %TEMP% or in %PROGRAMDATA%. Apply additional filters if necessary.

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ":\ProgramData\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Roaming\") AND TgtProcImagePath endswithCIS "\regsvr32.exe"))

```