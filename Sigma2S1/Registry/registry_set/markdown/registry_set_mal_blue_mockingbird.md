# registry_set_mal_blue_mockingbird

## Title
Blue Mockingbird - Registry

## ID
92b0b372-a939-44ed-a11b-5136cf680e27

## Author
Trent Liffick (@tliffick)

## Date
2020-05-14

## Tags
attack.execution, attack.t1112, attack.t1047

## Description
Attempts to detect system changes made by Blue Mockingbird

## References
https://redcanary.com/blog/blue-mockingbird-cryptominer/

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath endswithCIS "\CurrentControlSet\Services\wercplsupport\Parameters\ServiceDll")

```