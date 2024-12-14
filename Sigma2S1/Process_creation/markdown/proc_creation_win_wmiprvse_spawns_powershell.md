# proc_creation_win_wmiprvse_spawns_powershell

## Title
Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell

## ID
692f0bec-83ba-4d04-af7e-e884a96059b6

## Author
Markus Neis @Karneades

## Date
2019-04-03

## Tags
attack.execution, attack.t1047, attack.t1059.001

## Description
Detects Powershell as a child of the WmiPrvSE process. Which could be a sign of lateral movement via WMI.

## References
https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e

## False Positives
AppvClient
CCM
WinRM

## SentinelOne Query
```
EventType = "Process Creation" AND (EndpointOS = "windows" AND ((TgtProcImagePath endswithCIS "\powershell.exe" OR TgtProcImagePath endswithCIS "\pwsh.exe") AND SrcProcImagePath endswithCIS "\WmiPrvSE.exe"))

```