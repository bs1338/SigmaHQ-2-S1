# registry_set_persistence_mycomputer

## Title
Potential Persistence Via MyComputer Registry Keys

## ID
8fbe98a8-8f9d-44f8-aa71-8c572e29ef06

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2022-08-09

## Tags
attack.persistence

## Description
Detects modification to the "Default" value of the "MyComputer" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed (see reference section for example)

## References
https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/

## False Positives
Unlikely but if you experience FPs add specific processes and locations you would like to monitor for

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryKeyPath containsCIS "\Microsoft\Windows\CurrentVersion\Explorer\MyComputer" AND RegistryKeyPath endswithCIS "(Default)"))

```