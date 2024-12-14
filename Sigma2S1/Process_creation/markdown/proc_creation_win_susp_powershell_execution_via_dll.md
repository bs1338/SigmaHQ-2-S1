# proc_creation_win_susp_powershell_execution_via_dll

## Title
Potential PowerShell Execution Via DLL

## ID
6812a10b-60ea-420c-832f-dfcc33b646ba

## Author
Markus Neis, Nasreddine Bencherchali (Nextron Systems)

## Date
2018-08-25

## Tags
attack.defense-evasion, attack.t1218.011

## Description
Detects potential PowerShell execution from a DLL instead of the usual PowerShell process as seen used in PowerShdll.
This detection assumes that PowerShell commands are passed via the CommandLine.


## References
https://github.com/p3nt4/PowerShdll/blob/62cfa172fb4e1f7f4ac00ca942685baeb88ff356/README.md

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Default.GetString" OR TgtProcCmdLine containsCIS "DownloadString" OR TgtProcCmdLine containsCIS "FromBase64String" OR TgtProcCmdLine containsCIS "ICM " OR TgtProcCmdLine containsCIS "IEX " OR TgtProcCmdLine containsCIS "Invoke-Command" OR TgtProcCmdLine containsCIS "Invoke-Expression") AND (TgtProcImagePath endswithCIS "\InstallUtil.exe" OR TgtProcImagePath endswithCIS "\RegAsm.exe" OR TgtProcImagePath endswithCIS "\RegSvcs.exe" OR TgtProcImagePath endswithCIS "\regsvr32.exe" OR TgtProcImagePath endswithCIS "\rundll32.exe")))

```