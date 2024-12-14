# proc_creation_win_powershell_set_policies_to_unsecure_level

## Title
Change PowerShell Policies to an Insecure Level

## ID
87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180

## Author
frack113

## Date
2021-11-01

## Tags
attack.execution, attack.t1059.001

## Description
Detects changing the PowerShell script execution policy to a potentially insecure level using the "-ExecutionPolicy" flag.

## References
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.4
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4
https://adsecurity.org/?p=2604
https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/

## False Positives
Administrator scripts

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (TgtProcCmdLine containsCIS "Bypass" OR TgtProcCmdLine containsCIS "Unrestricted") AND (TgtProcCmdLine containsCIS "-executionpolicy " OR TgtProcCmdLine containsCIS " -ep " OR TgtProcCmdLine containsCIS " -exec ")))

```