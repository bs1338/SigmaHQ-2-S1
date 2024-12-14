# registry_set_persistence_xll

## Title
Potential Persistence Via Excel Add-in - Registry

## ID
961e33d1-4f86-4fcf-80ab-930a708b2f82

## Author
frack113

## Date
2023-01-15

## Tags
attack.persistence, attack.t1137.006

## Description
Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.

## References
https://github.com/redcanaryco/atomic-red-team/blob/4ae9580a1a8772db87a1b6cdb0d03e5af231e966/atomics/T1137.006/T1137.006.md
https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue endswithCIS ".xll" AND RegistryValue startswithCIS "/R " AND RegistryKeyPath containsCIS "Software\Microsoft\Office\" AND RegistryKeyPath endswithCIS "\Excel\Options"))

```