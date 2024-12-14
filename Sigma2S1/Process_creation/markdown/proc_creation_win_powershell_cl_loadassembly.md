# proc_creation_win_powershell_cl_loadassembly

## Title
Assembly Loading Via CL_LoadAssembly.ps1

## ID
c57872c7-614f-4d7f-a40d-b78c8df2d30d

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2022-05-21

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects calls to "LoadAssemblyFromPath" or "LoadAssemblyFromNS" that are part of the "CL_LoadAssembly.ps1" script. This can be abused to load different assemblies and bypass App locker controls.

## References
https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/
https://lolbas-project.github.io/lolbas/Scripts/CL_LoadAssembly/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (TgtProcCmdLine containsCIS "LoadAssemblyFromPath " OR TgtProcCmdLine containsCIS "LoadAssemblyFromNS "))

```