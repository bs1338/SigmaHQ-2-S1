# registry_set_defender_exclusions

## Title
Windows Defender Exclusions Added - Registry

## ID
a982fc9c-6333-4ffb-a51d-addb04e8b529

## Author
Christian Burkard (Nextron Systems)

## Date
2021-07-06

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects the Setting of Windows Defender Exclusions

## References
https://twitter.com/_nullbind/status/1204923340810543109

## False Positives
Administrator actions

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Microsoft\Windows Defender\Exclusions")

```