# registry_set_persistence_com_hijacking_builtin

## Title
COM Object Hijacking Via Modification Of Default System CLSID Default Value

## ID
790317c0-0a36-4a6a-a105-6e576bf99a14

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2024-07-16

## Tags
attack.persistence, attack.t1546.015

## Description
Detects potential COM object hijacking via modification of default system CLSID.

## References
https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/ (idea)
https://unit42.paloaltonetworks.com/snipbot-romcom-malware-variant/
https://blog.talosintelligence.com/uat-5647-romcom/
https://global.ptsecurity.com/analytics/pt-esc-threat-intelligence/darkhotel-a-cluster-of-groups-united-by-common-techniques

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (((RegistryKeyPath containsCIS "\{1f486a52-3cb1-48fd-8f50-b8dc300d9f9d}\" OR RegistryKeyPath containsCIS "\{2155fee3-2419-4373-b102-6843707eb41f}\" OR RegistryKeyPath containsCIS "\{4590f811-1d3a-11d0-891f-00aa004b2e24}\" OR RegistryKeyPath containsCIS "\{4de225bf-cf59-4cfc-85f7-68b90f185355}\" OR RegistryKeyPath containsCIS "\{ddc05a5a-351a-4e06-8eaf-54ec1bc2dcea}\" OR RegistryKeyPath containsCIS "\{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}\" OR RegistryKeyPath containsCIS "\{F82B4EF1-93A9-4DDE-8015-F7950A1A6E31}\" OR RegistryKeyPath containsCIS "\{7849596a-48ea-486e-8937-a2a3009f31a9}\" OR RegistryKeyPath containsCIS "\{0b91a74b-ad7c-4a9d-b563-29eef9167172}\") AND (RegistryKeyPath containsCIS "\CLSID\" AND (RegistryKeyPath endswithCIS "\InprocServer32\(Default)" OR RegistryKeyPath endswithCIS "\LocalServer32\(Default)"))) AND ((RegistryValue containsCIS ":\Perflogs\" OR RegistryValue containsCIS "\AppData\Local\" OR RegistryValue containsCIS "\Desktop\" OR RegistryValue containsCIS "\Downloads\" OR RegistryValue containsCIS "\Microsoft\Windows\Start Menu\Programs\Startup\" OR RegistryValue containsCIS "\System32\spool\drivers\color\" OR RegistryValue containsCIS "\Temporary Internet" OR RegistryValue containsCIS "\Users\Public\" OR RegistryValue containsCIS "\Windows\Temp\" OR RegistryValue containsCIS "%appdata%" OR RegistryValue containsCIS "%temp%" OR RegistryValue containsCIS "%tmp%") OR ((RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Favorites\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Favourites\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Contacts\") OR (RegistryValue containsCIS ":\Users\" AND RegistryValue containsCIS "\Pictures\")))))

```