# proc_creation_win_rundll32_unc_path

## Title
Rundll32 UNC Path Execution

## ID
5cdb711b-5740-4fb2-ba88-f7945027afac

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-10

## Tags
attack.defense-evasion, attack.execution, attack.t1021.002, attack.t1218.011

## Description
Detects rundll32 execution where the DLL is located on a remote location (share)

## References
https://www.cybereason.com/blog/rundll32-the-infamous-proxy-for-executing-malicious-code

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " \\" AND (TgtProcImagePath endswithCIS "\rundll32.exe" OR TgtProcCmdLine containsCIS "rundll32")))

```