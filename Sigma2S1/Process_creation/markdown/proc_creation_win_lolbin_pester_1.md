# proc_creation_win_lolbin_pester_1

## Title
Execute Code with Pester.bat

## ID
59e938ff-0d6d-4dc3-b13f-36cc28734d4e

## Author
Julia Fomina, oscd.community

## Date
2020-10-08

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1216

## Description
Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)

## References
https://twitter.com/Oddvarmoe/status/993383596244258816
https://github.com/api0cradle/LOLBAS/blob/d148d278f5f205ce67cfaf49afdfb68071c7252a/OSScripts/pester.md

## False Positives
Legitimate use of Pester for writing tests for Powershell scripts and modules

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "Pester" AND TgtProcCmdLine containsCIS "Get-Help") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe")) OR (((TgtProcCmdLine containsCIS "pester" AND TgtProcCmdLine containsCIS ";") AND TgtProcImagePath endswithCIS "\cmd.exe") AND (TgtProcCmdLine containsCIS "help" OR TgtProcCmdLine containsCIS "?"))))

```