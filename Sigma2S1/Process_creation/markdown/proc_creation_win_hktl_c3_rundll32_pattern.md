# proc_creation_win_hktl_c3_rundll32_pattern

## Title
HackTool - F-Secure C3 Load by Rundll32

## ID
b18c9d4c-fac9-4708-bd06-dd5bfacf200f

## Author
Alfie Champion (ajpc500)

## Date
2021-06-02

## Tags
attack.defense-evasion, attack.t1218.011

## Description
F-Secure C3 produces DLLs with a default exported StartNodeRelay function.

## References
https://github.com/FSecureLABS/C3/blob/11a081fd3be2aaf2a879f6b6e9a96ecdd24966ef/Src/NodeRelayDll/NodeRelayDll.cpp#L12

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "rundll32.exe" AND TgtProcCmdLine containsCIS ".dll" AND TgtProcCmdLine containsCIS "StartNodeRelay"))

```