# registry_set_disable_windows_defender_service

## Title
Windows Defender Service Disabled - Registry

## ID
e1aa95de-610a-427d-b9e7-9b46cfafbe6a

## Author
Ján Trenčanský, frack113, AlertIQ, Nasreddine Bencherchali

## Date
2022-08-01

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects when an attacker or tool disables the  Windows Defender service (WinDefend) via the registry

## References
https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105

## False Positives
Administrator actions

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000004)" AND RegistryKeyPath endswithCIS "\Services\WinDefend\Start"))

```