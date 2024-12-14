# proc_creation_win_rundll32_advpack_obfuscated_ordinal_call

## Title
Suspicious Advpack Call Via Rundll32.EXE

## ID
a1473adb-5338-4a20-b4c3-126763e2d3d3

## Author
Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)

## Date
2023-05-17

## Tags
attack.defense-evasion

## Description
Detects execution of "rundll32" calling "advpack.dll" with potential obfuscated ordinal calls in order to leverage the "RegisterOCX" function

## References
https://twitter.com/Hexacorn/status/1224848930795552769
http://www.hexacorn.com/blog/2020/02/05/stay-positive-lolbins-not/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "advpack" AND ((TgtProcCmdLine containsCIS "#+" AND TgtProcCmdLine containsCIS "12") OR TgtProcCmdLine containsCIS "#-") AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcCmdLine containsCIS "rundll32")))

```