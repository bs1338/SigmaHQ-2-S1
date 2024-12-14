# registry_set_persistence_autodial_dll

## Title
Potential Persistence Via AutodialDLL

## ID
e6fe26ee-d063-4f5b-b007-39e90aaf50e3

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-10

## Tags
attack.persistence

## Description
Detects change the the "AutodialDLL" key which could be used as a persistence method to load custom DLL via the "ws2_32" library

## References
https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/
https://persistence-info.github.io/Data/autodialdll.html

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND RegistryKeyPath containsCIS "\Services\WinSock2\Parameters\AutodialDLL")

```