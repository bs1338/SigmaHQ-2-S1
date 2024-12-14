# registry_set_file_association_exefile

## Title
New File Association Using Exefile

## ID
44a22d59-b175-4f13-8c16-cbaef5b581ff

## Author
Andreas Hunkeler (@Karneades)

## Date
2021-11-19

## Tags
attack.defense-evasion

## Description
Detects the abuse of the exefile handler in new file association. Used for bypass of security products.

## References
https://twitter.com/mrd0x/status/1461041276514623491

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "exefile" AND RegistryKeyPath containsCIS "Classes\."))

```