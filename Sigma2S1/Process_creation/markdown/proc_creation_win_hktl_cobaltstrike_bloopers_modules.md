# proc_creation_win_hktl_cobaltstrike_bloopers_modules

## Title
Operator Bloopers Cobalt Strike Modules

## ID
4f154fb6-27d1-4813-a759-78b93e0b9c48

## Author
_pete_0, TheDFIRReport

## Date
2022-05-06

## Tags
attack.execution, attack.t1059.003

## Description
Detects Cobalt Strike module/commands accidentally entered in CMD shell

## References
https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf
https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
https://thedfirreport.com/2022/06/16/sans-ransomware-summit-2022-can-you-detect-this/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Invoke-UserHunter" OR TgtProcCmdLine containsCIS "Invoke-ShareFinder" OR TgtProcCmdLine containsCIS "Invoke-Kerberoast" OR TgtProcCmdLine containsCIS "Invoke-SMBAutoBrute" OR TgtProcCmdLine containsCIS "Invoke-Nightmare" OR TgtProcCmdLine containsCIS "zerologon" OR TgtProcCmdLine containsCIS "av_query") AND TgtProcImagePath endswithCIS "\cmd.exe"))

```