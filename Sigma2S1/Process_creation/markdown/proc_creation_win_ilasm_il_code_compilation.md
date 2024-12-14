# proc_creation_win_ilasm_il_code_compilation

## Title
C# IL Code Compilation Via Ilasm.EXE

## ID
850d55f9-6eeb-4492-ad69-a72338f65ba4

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-07

## Tags
attack.defense-evasion, attack.t1127

## Description
Detects the use of "Ilasm.EXE" in order to compile C# intermediate (IL) code to EXE or DLL.

## References
https://lolbas-project.github.io/lolbas/Binaries/Ilasm/
https://www.echotrail.io/insights/search/ilasm.exe

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " /dll" OR TgtProcCmdLine containsCIS " /exe") AND TgtProcImagePath endswithCIS "\ilasm.exe"))

```