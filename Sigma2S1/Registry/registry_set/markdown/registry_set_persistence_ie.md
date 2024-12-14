# registry_set_persistence_ie

## Title
Modification of IE Registry Settings

## ID
d88d0ab2-e696-4d40-a2ed-9790064e66b3

## Author
frack113

## Date
2022-01-22

## Tags
attack.defense-evasion, attack.t1112

## Description
Detects modification of the registry settings used for Internet Explorer and other Windows components that use these settings. An attacker can abuse this registry key to add a domain to the trusted sites Zone or insert javascript for persistence

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-5---javascript-in-registry

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Software\Microsoft\Windows\CurrentVersion\Internet Settings" AND (NOT (RegistryKeyPath containsCIS "\Accepted Documents\" OR RegistryValue = "Binary Data" OR RegistryValue startswithCIS "DWORD" OR (RegistryValue In Contains AnyCase ("Cookie:","Visited:","(Empty)")) OR (RegistryKeyPath containsCIS "\Cache" OR RegistryKeyPath containsCIS "\ZoneMap" OR RegistryKeyPath containsCIS "\WpadDecision")))))

```