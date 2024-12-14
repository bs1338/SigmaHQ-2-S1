# registry_set_enable_anonymous_connection

## Title
Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback

## ID
4d431012-2ab5-4db7-a84e-b29809da2172

## Author
X__Junior (Nextron Systems)

## Date
2023-11-03

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects enabling of the "AllowAnonymousCallback" registry value, which allows a remote connection between computers that do not have a trust relationship.

## References
https://learn.microsoft.com/en-us/windows/win32/wmisdk/connecting-to-wmi-remotely-starting-with-vista

## False Positives
Administrative activity

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath containsCIS "\Microsoft\WBEM\CIMOM\AllowAnonymousCallback"))

```