# proc_creation_win_csc_susp_dynamic_compilation

## Title
Dynamic .NET Compilation Via Csc.EXE

## ID
dcaa3f04-70c3-427a-80b4-b870d73c94c4

## Author
Florian Roth (Nextron Systems), X__Junior (Nextron Systems)

## Date
2019-08-24

## Tags
attack.defense-evasion, attack.t1027.004

## Description
Detects execution of "csc.exe" to compile .NET code. Attackers often leverage this to compile code on the fly and use it in other stages.

## References
https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
https://twitter.com/gN3mes1s/status/1206874118282448897
https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1027.004/T1027.004.md#atomic-test-1---compile-after-delivery-using-cscexe

## False Positives
Legitimate software from program files - https://twitter.com/gN3mes1s/status/1206874118282448897
Legitimate Microsoft software - https://twitter.com/gabriele_pippi/status/1206907900268072962
Ansible

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcImagePath endswithCIS "\csc.exe" AND ((TgtProcCmdLine containsCIS ":\Perflogs\" OR TgtProcCmdLine containsCIS ":\Users\Public\" OR TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Temporary Internet" OR TgtProcCmdLine containsCIS "\Windows\Temp\") OR ((TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favorites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Favourites\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Contacts\") OR (TgtProcCmdLine containsCIS ":\Users\" AND TgtProcCmdLine containsCIS "\Pictures\")) OR TgtProcCmdLine RegExp "([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\\\[Aa]pp[Dd]ata\\\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\\\[^\\\\]{1,256}$") AND (NOT ((SrcProcImagePath startswithCIS "C:\Program Files (x86)\" OR SrcProcImagePath startswithCIS "C:\Program Files\") OR SrcProcImagePath = "C:\Windows\System32\sdiagnhost.exe" OR SrcProcImagePath = "C:\Windows\System32\inetsrv\w3wp.exe")) AND (NOT ((SrcProcCmdLine containsCIS "JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw" OR SrcProcCmdLine containsCIS "cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA" OR SrcProcCmdLine containsCIS "nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA") OR (SrcProcImagePath In Contains AnyCase ("C:\ProgramData\chocolatey\choco.exe","C:\ProgramData\chocolatey\tools\shimgen.exe")) OR SrcProcCmdLine containsCIS "\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"))))

```