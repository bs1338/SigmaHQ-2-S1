# proc_creation_win_hktl_cobaltstrike_load_by_rundll32

## Title
CobaltStrike Load by Rundll32

## ID
ae9c6a7c-9521-42a6-915e-5aaa8689d529

## Author
Wojciech Lesicki

## Date
2021-06-01

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.

## References
https://www.cobaltstrike.com/help-windows-executable
https://redcanary.com/threat-detection-report/
https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS ".dll" AND (TgtProcCmdLine endswithCIS " StartW" OR TgtProcCmdLine endswithCIS ",StartW")) AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR (TgtProcCmdLine containsCIS "rundll32.exe" OR TgtProcCmdLine containsCIS "rundll32 "))))

```