# proc_creation_win_aspnet_compiler_susp_child_process

## Title
Suspicious Child Process of AspNetCompiler

## ID
9ccba514-7cb6-4c5c-b377-700758f2f120

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-14

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects potentially suspicious child processes of "aspnet_compiler.exe".

## References
https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcImagePath endswithCIS "\calc.exe" OR TgtProcImagePath endswithCIS "\notepad.exe") OR (TgtProcImagePath containsCIS "\Users\Public\" OR TgtProcImagePath containsCIS "\AppData\Local\Temp\" OR TgtProcImagePath containsCIS "\AppData\Local\Roaming\" OR TgtProcImagePath containsCIS ":\Temp\" OR TgtProcImagePath containsCIS ":\Windows\Temp\" OR TgtProcImagePath containsCIS ":\Windows\System32\Tasks\" OR TgtProcImagePath containsCIS ":\Windows\Tasks\")) AND SrcProcImagePath endswithCIS "\aspnet_compiler.exe"))

```