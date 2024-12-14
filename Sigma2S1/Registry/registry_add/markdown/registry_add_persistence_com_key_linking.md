# registry_add_persistence_com_key_linking

## Title
Potential COM Object Hijacking Via TreatAs Subkey - Registry

## ID
9b0f8a61-91b2-464f-aceb-0527e0a45020

## Author
Kutepov Anton, oscd.community

## Date
2019-10-23

## Tags
attack.persistence, attack.t1546.015

## Description
Detects COM object hijacking via TreatAs subkey

## References
https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/

## False Positives
Maybe some system utilities in rare cases use linking keys for backward compatibility

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((EventType = "CreateKey" AND (RegistryKeyPath containsCIS "HKU\" AND RegistryKeyPath containsCIS "Classes\CLSID\" AND RegistryKeyPath containsCIS "\TreatAs")) AND (NOT SrcProcImagePath = "C:\WINDOWS\system32\svchost.exe")))

```