# proc_creation_win_rundll32_shell32_susp_execution

## Title
Shell32 DLL Execution in Suspicious Directory

## ID
32b96012-7892-429e-b26c-ac2bf46066ff

## Author
Christian Burkard (Nextron Systems)

## Date
2021-11-24

## Tags
attack.defense-evasion, attack.execution, attack.t1218.011

## Description
Detects shell32.dll executing a DLL in a suspicious directory

## References
https://www.group-ib.com/resources/threat-research/red-curl-2.html

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "%AppData%" OR TgtProcCmdLine containsCIS "%LocalAppData%" OR TgtProcCmdLine containsCIS "%Temp%" OR TgtProcCmdLine containsCIS "%tmp%" OR TgtProcCmdLine containsCIS "\AppData\" OR TgtProcCmdLine containsCIS "\Temp\" OR TgtProcCmdLine containsCIS "\Users\Public\") AND (TgtProcCmdLine containsCIS "shell32.dll" AND TgtProcCmdLine containsCIS "Control_RunDLL")) AND TgtProcImagePath endswithCIS "\rundll32.exe"))

```