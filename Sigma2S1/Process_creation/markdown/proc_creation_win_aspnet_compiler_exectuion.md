# proc_creation_win_aspnet_compiler_exectuion

## Title
AspNetCompiler Execution

## ID
a01b8329-5953-4f73-ae2d-aa01e1f35f00

## Author
frack113

## Date
2021-11-24

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects execution of "aspnet_compiler.exe" which can be abused to compile and execute C# code.

## References
https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath containsCIS "C:\Windows\Microsoft.NET\Framework\" OR TgtProcImagePath containsCIS "C:\Windows\Microsoft.NET\Framework64\") AND TgtProcImagePath endswithCIS "\aspnet_compiler.exe"))

```