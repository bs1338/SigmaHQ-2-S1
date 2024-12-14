# proc_creation_win_lolbin_pester

## Title
Execute Code with Pester.bat as Parent

## ID
18988e1b-9087-4f8a-82fe-0414dce49878

## Author
frack113, Nasreddine Bencherchali

## Date
2022-08-20

## Tags
attack.execution, attack.t1059.001, attack.defense-evasion, attack.t1216

## Description
Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)

## References
https://twitter.com/Oddvarmoe/status/993383596244258816
https://twitter.com/_st0pp3r_/status/1560072680887525378

## False Positives
Legitimate use of Pester for writing tests for Powershell scripts and modules

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((SrcProcCmdLine containsCIS "{ Invoke-Pester -EnableExit ;" OR SrcProcCmdLine containsCIS "{ Get-Help \"") AND (SrcProcCmdLine containsCIS "\WindowsPowerShell\Modules\Pester\" AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe"))))

```