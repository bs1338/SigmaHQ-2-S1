# proc_creation_win_winrm_execution_via_scripting_api_winrm_vbs

## Title
Remote Code Execute via Winrm.vbs

## ID
9df0dd3a-1a5c-47e3-a2bc-30ed177646a0

## Author
Julia Fomina, oscd.community

## Date
2020-10-07

## Tags
attack.defense-evasion, attack.t1216

## Description
Detects an attempt to execute code or create service on remote host via winrm.vbs.

## References
https://twitter.com/bohops/status/994405551751815170
https://redcanary.com/blog/lateral-movement-winrm-wmi/
https://lolbas-project.github.io/lolbas/Scripts/Winrm/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "winrm" AND TgtProcCmdLine containsCIS "invoke Create wmicimv2/Win32_" AND TgtProcCmdLine containsCIS "-r:http") AND TgtProcImagePath endswithCIS "\cscript.exe"))

```