# registry_set_uac_bypass_winsat

## Title
UAC Bypass Abusing Winsat Path Parsing - Registry

## ID
6597be7b-ac61-4ac8-bef4-d3ec88174853

## Author
Christian Burkard (Nextron Systems)

## Date
2021-08-30

## Tags
attack.defense-evasion, attack.privilege-escalation, attack.t1548.002

## Description
Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

## References
https://github.com/hfiref0x/UACME

## False Positives
Unknown

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue endswithCIS "\appdata\local\temp\system32\winsat.exe" AND RegistryValue startswithCIS "c:\users\" AND RegistryKeyPath containsCIS "\Root\InventoryApplicationFile\winsat.exe|" AND RegistryKeyPath endswithCIS "\LowerCaseLongPath"))

```