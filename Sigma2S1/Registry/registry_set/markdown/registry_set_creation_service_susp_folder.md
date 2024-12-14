# registry_set_creation_service_susp_folder

## Title
Service Binary in Suspicious Folder

## ID
a07f0359-4c90-4dc4-a681-8ffea40b4f47

## Author
Florian Roth (Nextron Systems), frack113

## Date
2022-05-02

## Tags
attack.defense-evasion, attack.t1112

## Description
Detect the creation of a service with a service binary located in a suspicious directory

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((((RegistryValue In Contains AnyCase ("DWORD (0x00000000)","DWORD (0x00000001)","DWORD (0x00000002)")) AND (SrcProcImagePath containsCIS "\Users\Public\" OR SrcProcImagePath containsCIS "\Perflogs\" OR SrcProcImagePath containsCIS "\ADMIN$\" OR SrcProcImagePath containsCIS "\Temp\") AND RegistryKeyPath endswithCIS "\Start" AND RegistryKeyPath startswithCIS "HKLM\System\CurrentControlSet\Services\") OR ((RegistryValue containsCIS "\Users\Public\" OR RegistryValue containsCIS "\Perflogs\" OR RegistryValue containsCIS "\ADMIN$\" OR RegistryValue containsCIS "\Temp\") AND RegistryKeyPath endswithCIS "\ImagePath" AND RegistryKeyPath startswithCIS "HKLM\System\CurrentControlSet\Services\")) AND (NOT (SrcProcImagePath containsCIS "\Common Files\" AND SrcProcImagePath containsCIS "\Temp\"))))

```