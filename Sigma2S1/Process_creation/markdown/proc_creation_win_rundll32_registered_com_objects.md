# proc_creation_win_rundll32_registered_com_objects

## Title
Rundll32 Registered COM Objects

## ID
f1edd233-30b5-4823-9e6a-c4171b24d316

## Author
frack113

## Date
2022-02-13

## Tags
attack.privilege-escalation, attack.persistence, attack.t1546.015

## Description
load malicious registered COM objects

## References
https://nasbench.medium.com/a-deep-dive-into-rundll32-exe-642344b41e90
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1546.015/T1546.015.md

## False Positives
Legitimate use

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "-sta " OR TgtProcCmdLine containsCIS "-localserver ") AND (TgtProcCmdLine containsCIS "{" AND TgtProcCmdLine containsCIS "}")) AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```