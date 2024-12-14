# proc_creation_win_werfault_reflect_debugger_exec

## Title
Potential ReflectDebugger Content Execution Via WerFault.EXE

## ID
fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd

## Author
X__Junior (Nextron Systems)

## Date
2023-06-30

## Tags
attack.execution, attack.defense-evasion, attack.t1036

## Description
Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to masquerade the execution flow

## References
https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS " -pr " AND TgtProcImagePath endswithCIS "\WerFault.exe"))

```