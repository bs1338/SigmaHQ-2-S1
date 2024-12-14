# registry_set_winget_enable_local_manifest

## Title
Enable Local Manifest Installation With Winget

## ID
fa277e82-9b78-42dd-b05c-05555c7b6015

## Author
Nasreddine Bencherchali (Nextron Systems)

## Date
2023-04-17

## Tags
attack.defense-evasion, attack.persistence

## Description
Detects changes to the AppInstaller (winget) policy. Specifically the activation of the local manifest installation, which allows a user to install new packages via custom manifests.

## References
https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget

## False Positives
Administrators or developers might enable this for testing purposes or to install custom private packages

## SentinelOne Query
```
ObjectType = "Registry" AND (EndpointOS = "windows" AND (RegistryValue = "DWORD (0x00000001)" AND RegistryKeyPath endswithCIS "\AppInstaller\EnableLocalManifestFiles"))

```