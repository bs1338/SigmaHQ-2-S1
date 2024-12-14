# registry_set_office_enable_dde

## Title
Enable Microsoft Dynamic Data Exchange

## ID
63647769-326d-4dde-a419-b925cc0caf42

## Author
frack113

## Date
2022-02-26

## Tags
attack.execution, attack.t1559.002

## Description
Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel.

## References
https://msrc.microsoft.com/update-guide/vulnerability/ADV170021

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\Excel\Security\DisableDDEServerLaunch" OR RegistryKeyPath endswithCIS "\Excel\Security\DisableDDEServerLookup")) OR ((RegistryValue In Contains AnyCase ("DWORD (0x00000001)","DWORD (0x00000002)")) AND RegistryKeyPath endswithCIS "\Word\Security\AllowDDE")))

```