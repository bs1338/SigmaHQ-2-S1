# proc_creation_win_odbcconf_response_file_susp

## Title
Suspicious Response File Execution Via Odbcconf.EXE

## ID
2d32dd6f-3196-4093-b9eb-1ad8ab088ca5

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-22

## Tags
attack.defense-evasion, attack.t1218.008

## Description
Detects execution of "odbcconf" with the "-f" flag in order to load a response file with a non-".rsp" extension.

## References
https://learn.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-ver16
https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
https://www.trendmicro.com/en_us/research/17/h/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses.html

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS " -f " OR TgtProcCmdLine containsCIS " /f " OR TgtProcCmdLine containsCIS " â€“f " OR TgtProcCmdLine containsCIS " â€”f " OR TgtProcCmdLine containsCIS " â€•f ") AND TgtProcImagePath endswithCIS "\odbcconf.exe") AND (NOT (TgtProcCmdLine containsCIS ".rsp" OR (TgtProcCmdLine containsCIS ".exe /E /F \"C:\WINDOWS\system32\odbcconf.tmp\"" AND TgtProcImagePath = "C:\Windows\System32\odbcconf.exe" AND SrcProcImagePath = "C:\Windows\System32\runonce.exe")))))

```