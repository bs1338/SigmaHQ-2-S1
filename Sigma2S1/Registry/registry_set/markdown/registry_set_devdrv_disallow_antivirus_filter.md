# registry_set_devdrv_disallow_antivirus_filter

## Title
Antivirus Filter Driver Disallowed On Dev Drive - Registry

## ID
31e124fb-5dc4-42a0-83b3-44a69c77b271

## Author
@kostastsale, Nasreddine Bencherchali (Nextron Systems)

## Date
2023-11-05

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects activity that indicates a user disabling the ability for Antivirus mini filter to inspect a "Dev Drive".


## References
https://twitter.com/0gtweet/status/1720419490519752955

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000000)" AND RegistryKeyPath endswithCIS "\FilterManager\FltmgrDevDriveAllowAntivirusFilter"))

```