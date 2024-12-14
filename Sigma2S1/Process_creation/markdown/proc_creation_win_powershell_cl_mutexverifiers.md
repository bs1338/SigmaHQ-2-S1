# proc_creation_win_powershell_cl_mutexverifiers

## Title
Potential Script Proxy Execution Via CL_Mutexverifiers.ps1

## ID
1e0e1a81-e79b-44bc-935b-ddb9c8006b3d

## Author
Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113

## Date
2022-05-21

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands

## References
https://lolbas-project.github.io/lolbas/Scripts/CL_mutexverifiers/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS " -nologo -windowstyle minimized -file " AND TgtProcImagePath endswithCIS "\powershell.exe" AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")) AND (TgtProcCmdLine containsCIS "\AppData\Local\Temp\" OR TgtProcCmdLine containsCIS "\Windows\Temp\")))

```