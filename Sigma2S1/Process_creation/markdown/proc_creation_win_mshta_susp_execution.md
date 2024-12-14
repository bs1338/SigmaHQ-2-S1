# proc_creation_win_mshta_susp_execution

## Title
MSHTA Suspicious Execution 01

## ID
cc7abbd0-762b-41e3-8a26-57ad50d2eea3

## Author
Diego Perez (@darkquassar), Markus Neis, Swisscom (Improve Rule)

## Date
2019-02-22

## Tags
attack.defense-evasion, attack.t1140, attack.t1218.005, attack.execution, attack.t1059.007, cve.2020-1599

## Description
Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism

## References
http://blog.sevagas.com/?Hacking-around-HTA-files
https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356
https://learn.microsoft.com/en-us/previous-versions/dotnet/framework/data/xml/xslt/xslt-stylesheet-scripting-using-msxsl-script
https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997
https://twitter.com/mattifestation/status/1326228491302563846

## False Positives
False positives depend on scripts and administrative tools used in the monitored environment

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "vbscript" OR TgtProcCmdLine containsCIS ".jpg" OR TgtProcCmdLine containsCIS ".png" OR TgtProcCmdLine containsCIS ".lnk" OR TgtProcCmdLine containsCIS ".xls" OR TgtProcCmdLine containsCIS ".doc" OR TgtProcCmdLine containsCIS ".zip" OR TgtProcCmdLine containsCIS ".dll") AND TgtProcImagePath endswithCIS "\mshta.exe"))

```