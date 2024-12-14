# registry_set_office_disable_protected_view_features

## Title
Microsoft Office Protected View Disabled

## ID
a5c7a43f-6009-4a8c-80c5-32abf1c53ecc

## Author
frack113, Nasreddine Bencherchali (Nextron Systems)

## Date
2021-06-08

## Tags
attack.defense-evasion, attack.t1562.001

## Description
Detects changes to Microsoft Office protected view registry keys with which the attacker disables this feature.

## References
https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
https://yoroi.company/research/cyber-criminal-espionage-operation-insists-on-italian-manufacturing/
https://admx.help/HKCU/software/policies/microsoft/office/16.0/excel/security/protectedview

## False Positives
Unlikely

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND ((RegistryKeyPath containsCIS "\SOFTWARE\Microsoft\Office\" AND RegistryKeyPath containsCIS "\Security\ProtectedView\") AND ((RegistryValue = "DWORD (0x00000000)" AND (RegistryKeyPath endswithCIS "\enabledatabasefileprotectedview" OR RegistryKeyPath endswithCIS "\enableforeigntextfileprotectedview")) OR (RegistryValue = "DWORD (0x00000001)" AND (RegistryKeyPath endswithCIS "\DisableAttachementsInPV" OR RegistryKeyPath endswithCIS "\DisableInternetFilesInPV" OR RegistryKeyPath endswithCIS "\DisableIntranetCheck" OR RegistryKeyPath endswithCIS "\DisableUnsafeLocationsInPV")))))

```