# proc_creation_win_rundll32_shelldispatch_potential_abuse

## Title
Potential ShellDispatch.DLL Functionality Abuse

## ID
82343930-652f-43f5-ab70-2ee9fdd6d5e9

## Author
X__Junior (Nextron Systems)

## Date
2023-06-20

## Tags
attack.execution, attack.defense-evasion

## Description
Detects potential "ShellDispatch.dll" functionality abuse to execute arbitrary binaries via "ShellExecute"

## References
https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/

## False Positives
Unlikely

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "RunDll_ShellExecuteW" AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```