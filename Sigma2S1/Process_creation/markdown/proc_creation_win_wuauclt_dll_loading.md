# proc_creation_win_wuauclt_dll_loading

## Title
Proxy Execution Via Wuauclt.EXE

## ID
af77cf95-c469-471c-b6a0-946c685c4798

## Author
Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), Florian Roth (Nextron Systems), Sreeman, FPT.EagleEye Team

## Date
2020-10-12

## Tags
attack.defense-evasion, attack.t1218, attack.execution

## Description
Detects the use of the Windows Update Client binary (wuauclt.exe) for proxy execution.

## References
https://dtm.uk/wuauclt/
https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND (((TgtProcCmdLine containsCIS "UpdateDeploymentProvider" AND TgtProcCmdLine containsCIS "RunHandlerComServer") AND TgtProcImagePath endswithCIS "\wuauclt.exe") AND (NOT (TgtProcCmdLine containsCIS " /UpdateDeploymentProvider UpdateDeploymentProvider.dll " OR (TgtProcCmdLine containsCIS ":\Windows\UUS\Packages\Preview\amd64\updatedeploy.dll /ClassId" OR TgtProcCmdLine containsCIS ":\Windows\UUS\amd64\UpdateDeploy.dll /ClassId") OR (TgtProcCmdLine containsCIS ":\Windows\WinSxS\" AND TgtProcCmdLine containsCIS "\UpdateDeploy.dll /ClassId ") OR TgtProcCmdLine containsCIS " wuaueng.dll "))))

```