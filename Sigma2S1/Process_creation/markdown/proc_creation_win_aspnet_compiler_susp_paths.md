# proc_creation_win_aspnet_compiler_susp_paths

## Title
Potentially Suspicious ASP.NET Compilation Via AspNetCompiler

## ID
9f50fe98-fe5c-4a2d-86c7-fad7f63ed622

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-14

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects execution of "aspnet_compiler.exe" with potentially suspicious paths for compilation.

## References
https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "\Users\Public\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\AppData\Local\Roaming\" OR TgtProcCmdLine containsCIS ":\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\Temp\" OR TgtProcCmdLine containsCIS ":\Windows\System32\Tasks\" OR TgtProcCmdLine containsCIS ":\Windows\Tasks\") AND (TgtProcImagePath containsCIS "C:\Windows\Microsoft.NET\Framework\" OR TgtProcImagePath containsCIS "C:\Windows\Microsoft.NET\Framework64\") AND TgtProcImagePath endswithCIS "\aspnet_compiler.exe"))

```