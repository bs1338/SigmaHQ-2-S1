# registry_set_bginfo_custom_wmi_query

## Title
New BgInfo.EXE Custom WMI Query Registry Configuration

## ID
cd277474-5c52-4423-a52b-ac2d7969902f

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-08-16

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom WMI query via "BgInfo.exe"

## References
Internal Research

## False Positives
Legitimate WMI query

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue startswithCIS "6" AND EventType = "SetValue" AND RegistryKeyPath containsCIS "\Software\Winternals\BGInfo\UserFields\"))

```