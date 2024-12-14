# proc_creation_win_powershell_run_script_from_ads

## Title
Run PowerShell Script from ADS

## ID
45a594aa-1fbd-4972-a809-ff5a99dd81b8

## Author
Sergey Soldatov, Kaspersky Lab, oscd.community

## Date
2019-10-30

## Tags
attack.defense-evasion, attack.t1564.004

## Description
Detects PowerShell script execution from Alternate Data Stream (ADS)

## References
https://github.com/p0shkatz/Get-ADS/blob/1c3a3562e713c254edce1995a7d9879c687c7473/Get-ADS.ps1

## False Positives
Unknown

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcCmdLine containsCIS "Get-Content" AND TgtProcCmdLine containsCIS "-Stream") AND (TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND (SrcProcImagePath endswithCIS "\powershell.exe" OR SrcProcImagePath endswithCIS "\pwsh.exe")))

```