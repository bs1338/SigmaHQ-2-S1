# proc_creation_win_mshta_susp_pattern

## Title
Suspicious Mshta.EXE Execution Patterns

## ID
e32f92d1-523e-49c3-9374-bdb13b46a3ba

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2021-07-17

## Tags
attack.execution, attack.t1106

## Description
Detects suspicious mshta process execution patterns

## References
https://en.wikipedia.org/wiki/HTML_Application
https://www.echotrail.io/insights/search/mshta.exe
https://app.any.run/tasks/34221348-072d-4b70-93f3-aa71f6ebecad/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\mshta.exe" AND ((TgtProcCmdLine containsCIS "\AppData\Local\" OR TgtProcCmdLine containsCIS "C:\ProgramData\" OR TgtProcCmdLine containsCIS "C:\Users\Public\" OR TgtProcCmdLine containsCIS "C:\Windows\Temp\") AND (SrcProcImagePath endswithCIS "\cmd.exe" OR SrcProcImagePath endswithCIS "\cscript.exe" OR SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe" OR SrcProcImagePath endswithCIS "\regsvr32.exe" OR SrcProcImagePath endswithCIS "\rundll32.exe" OR SrcProcImagePath endswithCIS "\wscript.exe"))) OR (TgtProcImagePath endswithCIS "\mshta.exe" AND (NOT ((TgtProcImagePath startswithCIS "C:\Windows\System32\" OR TgtProcImagePath startswithCIS "C:\Windows\SysWOW64\") OR (TgtProcCmdLine containsCIS ".htm" OR TgtProcCmdLine containsCIS ".hta") OR (TgtProcCmdLine endswithCIS "mshta.exe" OR TgtProcCmdLine endswithCIS "mshta"))))))

```