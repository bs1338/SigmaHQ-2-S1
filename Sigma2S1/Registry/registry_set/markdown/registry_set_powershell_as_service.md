# registry_set_powershell_as_service

## Title
PowerShell as a Service in Registry

## ID
4a5f5a5e-ac01-474b-9b4e-d61298c9df1d

## Author
oscd.community, Natalia Shornikova

## Date
2020-10-06

## Tags
attack.execution, attack.t1569.002

## Description
Detects that a powershell code is written to the registry as a service.

## References
https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue containsCIS "powershell" OR RegistryValue containsCIS "pwsh") AND RegistryKeyPath containsCIS "\Services\" AND RegistryKeyPath endswithCIS "\ImagePath"))

```